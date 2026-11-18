"""Ansible-UI - schlanke deutsche Weboberflaeche fuer Ansible mit Maschinenliste.

Daten (Volume /data):
  hosts.json        Maschinen (Name, Adresse, Gruppe, Benutzer, Port, aktiv, Notiz)
  status.json       letzter Ping / Fakten-Zeitpunkt je Maschine
  facts/<name>.json gesammelte Ansible-Fakten
  secrets.json      Zugangsprofile + Standardprofil je Gruppe (0600, Passwoerter werden nie angezeigt)
  auth.json         Hash des Admin-Passworts (0600)
  ssh/id_ed25519    SSH-Schluessel fuer Linux (oeffentlicher Teil in den Einstellungen)
  playbooks/*.yml   Playbooks
  runs/             Protokolle aller Laeufe
  settings.json     Einstellungen (naechtliche Update-Pruefung)
"""
import datetime
import hashlib
import json
import os
import re
import secrets
import smtplib
import socket
import ssl
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import time
import tempfile
import threading
import urllib.parse
import uuid
from functools import wraps

import yaml
from flask import Flask, abort, flash, has_request_context, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from jinja2 import DictLoader

DATA = os.environ.get("DATA_DIR", "/data")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
ADDR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
PB_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.ya?ml$")
PID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
USER_RE = re.compile(r"^[A-Za-z0-9._@\\$-]{1,64}$")
GROUPS = ("linux", "windows")
DEFAULT_LOCATIONS = [
    {"name": "Standard", "nets": []},
]
LOCNAME_RE = re.compile(r"^[^<>\"'&/\\]{1,40}$")
NET_RE = re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){0,3}\.?$")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
LOCK = threading.RLock()


# ---------------------------------------------------------------- Speicher
def p(*parts):
    return os.path.join(DATA, *parts)


def load(name, default):
    try:
        with open(p(name)) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save(name, obj, mode=0o644):
    with LOCK:
        tmp = p(name + ".tmp")
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=1, ensure_ascii=False)
        os.chmod(tmp, mode)
        os.replace(tmp, p(name))


def locations():
    """Standorte in Anzeige-Reihenfolge: [{"name", "nets": [Netz-Praefixe]}]."""
    with LOCK:
        locs = load("locations.json", None)
        if not locs:
            locs = [dict(x) for x in DEFAULT_LOCATIONS]
            save("locations.json", locs)
        return locs


def loc_names():
    return [x["name"] for x in locations()]


def addr_list(h):
    """Adressfeld -> Liste ("192.168.1.10, 192.168.1.11" = LAN, dann WLAN)."""
    return [a for a in re.split(r"[,;\s]+", h.get("address") or "") if a]


def default_port(h):
    return int(h.get("port") or (5985 if h.get("group") == "windows" else 22))


def tcp_ok(addr, port, timeout=1.5):
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            return True
    except OSError:
        return False


def pick_addresses(hs):
    """Fuer Maschinen mit mehreren Adressen: alle gleichzeitig kurz pruefen, die erste erreichbare (in der eingetragenen
    Reihenfolge) nehmen. Ergebnis {name: (adresse, erreicht)}; wird in status.json als "via" vermerkt."""
    multi = [h for h in hs if len(addr_list(h)) > 1]
    if not multi:
        return {}
    jobs = [(h, a) for h in multi for a in addr_list(h)]
    with ThreadPoolExecutor(max_workers=min(32, len(jobs))) as ex:
        ok = dict(zip([(h["name"], a) for h, a in jobs], ex.map(lambda x: tcp_ok(x[1], default_port(x[0])), jobs)))
    out = {}
    for h in multi:
        hit = next((a for a in addr_list(h) if ok[(h["name"], a)]), None)
        out[h["name"]] = (hit or addr_list(h)[0], bool(hit))
    with LOCK:
        st = load("status.json", {})
        for n, (a, reached) in out.items():
            st.setdefault(n, {})["via"] = {"addr": a, "ok": reached, "time": now()}
        save("status.json", st)
    return out


def guess_location(h):
    """Standort aus Adresse bzw. Namen ableiten (fuer Maschinen ohne gesetzten Standort)."""
    locs = locations()
    addr = (addr_list(h) or [""])[0]
    text = (addr + " " + h.get("name", "")).lower()
    best = ""
    for x in locs:  # laengstes passendes Netz gewinnt
        for net in x.get("nets", []):
            if addr.startswith(net) and len(net) > len(best):
                best, site = net, x["name"]
    if best:
        return site
    for x in locs[1:]:
        if x["name"].lower() in text:
            return x["name"]
    return locs[0]["name"]


def slugify(text):
    """Technischen Namen (Ansible-Hostname) aus einem Anzeigenamen bilden."""
    s = text.lower()
    for a, b in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss")):
        s = s.replace(a, b)
    s = re.sub(r"[^a-z0-9._-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-._")
    return s[:63]


def display_name(h):
    return h.get("display") or h.get("name", "")


def loc_index(loc):
    names = loc_names()
    return names.index(loc) if loc in names else len(names)


def hosts():
    with LOCK:
        h = load("hosts.json", None)
        if h is None:
            with open("/app/seed.json") as f:
                h = json.load(f)["hosts"]
            save("hosts.json", h)
        if any(not x.get("location") for x in h):
            for x in h:
                x["location"] = x.get("location") or guess_location(x)
            save("hosts.json", h)
        return sorted(h, key=lambda x: (loc_index(x.get("location")), not x.get("enabled", True), x["group"], display_name(x).lower()))


def host(name):
    for h in hosts():
        if h["name"] == name:
            return h
    abort(404)


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def facts_of(name):
    try:
        with open(p("facts", name + ".json")) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def summary(f):
    if not f:
        return {}
    if f.get("ansible_os_family") == "Windows" or "ansible_os_name" in f:
        os_name = f.get("ansible_os_name") or f.get("ansible_distribution", "")
    else:
        os_name = " ".join(x for x in (f.get("ansible_distribution"), f.get("ansible_distribution_version")) if x)
    mem = f.get("ansible_memtotal_mb")
    up = f.get("ansible_uptime_seconds")
    return {
        "os": os_name,
        "kernel": f.get("ansible_kernel", ""),
        "hostname": f.get("ansible_fqdn") or f.get("ansible_hostname", ""),
        "ips": ", ".join(x for x in f.get("ansible_all_ipv4_addresses", []) if not x.startswith("172.")),
        "cpu": f.get("ansible_processor_vcpus") or f.get("ansible_processor_cores") or "",
        "ram": f"{round(mem / 1024, 1)} GB" if mem else "",
        "uptime": f"{int(up) // 86400} T {int(up) % 86400 // 3600} h" if up else "",
        "virt": f.get("ansible_virtualization_type", ""),
        "arch": f.get("ansible_architecture", ""),
    }


# ---------------------------------------------------------------- Zugangsprofile
def blank_profile(kind):
    return {"id": "", "name": "", "type": kind, "user": "", "auth": "key" if kind == "linux" else "password",
            "password": "", "become": "sudo" if kind == "linux" else "none", "become_user": "root",
            "become_password": "", "transport": "ntlm"}


def profiles_data():
    """Zugangsprofile und Standardprofil je Gruppe; uebernimmt beim ersten Aufruf die alten Einzel-Einstellungen."""
    with LOCK:
        sec = load("secrets.json", {})
        if "profiles" not in sec:
            lin = blank_profile("linux")
            lin.update(id="linux-standard", name="Linux Standard (SSH-Schlüssel)",
                       become_password=sec.get("become_password", ""))
            win = blank_profile("windows")
            win.update(id="windows-standard", name="Windows Standard", user=sec.get("win_user", ""),
                       password=sec.get("win_password", ""), transport=sec.get("win_transport") or "ntlm")
            sec = {"profiles": [lin, win], "defaults": {"linux": "linux-standard", "windows": "windows-standard"}}
            save("secrets.json", sec, 0o600)
        return sec


def profile_for(h, sec=None):
    sec = sec or profiles_data()
    pid = h.get("profile") or sec["defaults"].get(h["group"])
    return next((x for x in sec["profiles"] if x["id"] == pid), None)


def profile_label(pr):
    if not pr:
        return "kein Profil"
    if pr["type"] == "windows":
        return f'{pr["user"] or "?"} (WinRM {pr["transport"]})'
    login = "Schlüssel" if pr["auth"] == "key" else "Passwort"
    rights = {"none": "", "sudo": " → sudo", "su": " → su"}[pr["become"]]
    if pr["become"] != "none":
        rights += f' {pr["become_user"] or "root"}'
    return f'{pr["user"] or "Standardbenutzer"} ({login}){rights}'


# ---------------------------------------------------------------- Ansible
def write_inventory():
    """Inventar mit Zugangsdaten je Maschine als temporaere Datei (0600); Aufrufer loescht sie."""
    sec = profiles_data()
    ssh_args = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10"
    inv = {"all": {"children": {
        "linux": {"hosts": {}, "vars": {"ansible_ssh_common_args": ssh_args, "ansible_python_interpreter": "auto_silent"}},
        "windows": {"hosts": {}, "vars": {
            "ansible_connection": "winrm",
            "ansible_winrm_server_cert_validation": "ignore",
            "ansible_winrm_operation_timeout_sec": 20,
            "ansible_winrm_read_timeout_sec": 30}},
    }}}
    act = [h for h in hosts() if h.get("enabled", True) and h.get("address")]
    chosen = pick_addresses(act)
    for h in act:
        pr = profile_for(h, sec) or blank_profile(h["group"])
        hv = {"ansible_host": chosen[h["name"]][0] if h["name"] in chosen else addr_list(h)[0]}
        if h.get("port"):
            hv["ansible_port"] = int(h["port"])
        user = h.get("user") or pr.get("user")
        if user:
            hv["ansible_user"] = user
        if h["group"] == "windows":
            hv["ansible_winrm_transport"] = pr.get("transport") or "ntlm"
            if pr.get("password"):
                hv["ansible_password"] = pr["password"]
        else:
            if pr.get("auth") == "password":
                hv["ansible_password"] = pr.get("password", "")
                hv["ansible_ssh_common_args"] = ssh_args + " -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive"
            else:
                hv["ansible_ssh_private_key_file"] = p("ssh", "id_ed25519")
            if pr.get("become") in ("sudo", "su"):
                hv["ansible_become_method"] = pr["become"]
                hv["ansible_become_user"] = pr.get("become_user") or "root"
                if pr.get("become_password"):
                    hv["ansible_become_password"] = pr["become_password"]
        inv["all"]["children"][h["group"]]["hosts"][h["name"]] = hv
    fd, path = tempfile.mkstemp(prefix="inv-", suffix=".yml")
    with os.fdopen(fd, "w") as f:
        yaml.safe_dump(inv, f)
    os.chmod(path, 0o600)
    return path


def new_run(kind, target, title, names=None):
    rid = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
    with LOCK:
        runs = load("runs/index.json", [])
        runs.insert(0, {"id": rid, "kind": kind, "target": target, "title": title, "start": now(),
                        "end": None, "status": "laeuft", **({"hosts": list(names)} if names else {}),
                        "user": session.get("user", "") if has_request_context() else "automatisch"})
        save("runs/index.json", runs[:500])
    return rid


def finish_run(rid, status):
    with LOCK:
        runs = load("runs/index.json", [])
        for r in runs:
            if r["id"] == rid:
                r["status"], r["end"] = status, now()
        save("runs/index.json", runs)


def env_json():
    e = dict(os.environ)
    e.update(ANSIBLE_LOAD_CALLBACK_PLUGINS="1", ANSIBLE_STDOUT_CALLBACK="json")
    return e


def explain(raw):
    """Ansible-Fehlermeldung kuerzen (SSH-Warnungen raus) und einen deutschen Hinweis voranstellen."""
    lines = [x.strip() for x in str(raw).splitlines()
             if x.strip() and not x.strip().startswith(("Warning: Permanently added", "** WARNING"))]
    text = " ".join(lines).replace("Task failed: ", "").replace("Failed to connect to the host via ssh: ", "SSH: ")
    text = re.sub(r"Warning: Permanently added '[^']*' \([^)]*\) to the list of known hosts\.\s*", "", text).strip()
    hints = (("Permission denied", "Anmeldung abgelehnt – SSH-Schlüssel nicht eingetragen oder Benutzer/Passwort falsch. "),
             ("Connection timed out", "Keine Verbindung (Zeitüberschreitung) – Adresse, Port oder Firewall prüfen. "),
             ("Connection refused", "Port geschlossen – läuft SSH/WinRM auf dem angegebenen Port? "),
             ("No route to host", "Maschine nicht erreichbar (aus oder falsches Netz). "),
             ("credentials were rejected", "Windows-Anmeldung abgelehnt – Benutzer/Passwort im Profil prüfen. "),
             ("Incorrect su password", "su-Passwort falsch. "),
             ("Fehler bei Authentifizierung", "su-/sudo-Passwort falsch oder fehlt im Profil. "),
             ("Authentication failure", "su-/sudo-Passwort falsch oder fehlt im Profil. "),
             ("Missing sudo password", "sudo verlangt ein Passwort – im Profil eintragen. "))
    hint = next((h for k, h in hints if k.lower() in text.lower()), "")
    return (hint + text)[:400]


def adhoc_job(rid, kind, names):
    """Ping oder Fakten fuer eine Liste von Maschinen; Ergebnis in status.json/facts."""
    inv = write_inventory()
    log = open(p("runs", rid + ".log"), "w")
    ok_all = True
    try:
        by_group = {}
        for n in names:
            h = host(n)
            by_group.setdefault(h["group"], []).append(n)
        for group, members in by_group.items():
            module = ("win_ping" if group == "windows" else "ping") if kind == "ping" else \
                     ("setup")
            if kind == "facts" and group == "windows":
                module = "ansible.windows.setup"
            cmd = ["ansible", ",".join(members), "-i", inv, "-m", module, "--forks", "10", "-T", "20"]
            log.write(f"$ ansible {','.join(members)} -m {module}\n")
            log.flush()
            r = subprocess.run(cmd, capture_output=True, text=True, env=env_json(), timeout=600)
            try:
                out = json.loads(r.stdout[r.stdout.index("{"):])
                results = out["plays"][0]["tasks"][0]["hosts"]
            except (ValueError, KeyError, IndexError):
                log.write(r.stdout[-5000:] + "\n" + r.stderr[-5000:] + "\n")
                ok_all = False
                results = {}
            with LOCK:
                st = load("status.json", {})
                for n in members:
                    res = results.get(n)
                    s = st.setdefault(n, {})
                    if res is None:
                        s.update(ping_ok=False, ping_time=now(), ping_msg="keine Antwort von Ansible")
                        ok_all = False
                        log.write(f"{n}: keine Antwort\n")
                        continue
                    bad = res.get("unreachable") or res.get("failed")
                    msg = explain(res.get("msg") or res.get("stderr") or "") if bad else "erreichbar"
                    s.update(ping_ok=not bad, ping_time=now(), ping_msg=msg)
                    log.write(f"{n}: {'FEHLER - ' + msg if bad else 'ok'}\n")
                    if bad:
                        ok_all = False
                    elif kind == "facts" and res.get("ansible_facts"):
                        with open(p("facts", n + ".json"), "w") as f:
                            json.dump(res["ansible_facts"], f, indent=1, default=str)
                        s["facts_time"] = now()
                save("status.json", st)
            log.flush()
    except Exception as ex:  # noqa: BLE001
        log.write(f"Fehler: {ex}\n")
        ok_all = False
    finally:
        log.close()
        os.unlink(inv)
        finish_run(rid, "ok" if ok_all else "Fehler")


# ---------------------------------------------------------------- Update-Pruefung
# Eingebautes Pruef-Playbook: sucht nur, installiert nichts. Linux: Paketverwaltung wird erkannt (apt, dnf/yum, zypper),
# Windows 10/11/Server: Windows Update im Suchmodus.
UPD_CHECK_PB = r"""
- name: Linux
  hosts: linux
  gather_facts: false
  tasks:
    - name: Updates suchen (Linux)
      become: "{{ ansible_become_method is defined }}"
      changed_when: false
      ignore_errors: true
      ignore_unreachable: true
      register: upd_root
      ansible.builtin.shell: &upd_script |
        LC_ALL=C; export LC_ALL
        if command -v apt-get >/dev/null 2>&1; then
          echo "PM apt"
          apt-get update -qq >/dev/null 2>&1 || echo "WARN Paketlisten konnten nicht aktualisiert werden (Root-Rechte?) - Stand der letzten Aktualisierung"
          apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep '^Inst ' | sed 's/^/APT /'
          [ -f /var/run/reboot-required ] && echo REBOOT
        elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
          if command -v dnf >/dev/null 2>&1; then PM=dnf; else PM=yum; fi
          echo "PM $PM"
          $PM -q check-update 2>/dev/null | awk 'NF==3 && $1 ~ /\./ {print "RPM "$1" "$2" "$3}'
          $PM -q updateinfo list --security 2>/dev/null | awk 'NF>=3 {print "SEC "$3}'
          if command -v needs-restarting >/dev/null 2>&1; then
            needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ] && echo REBOOT
          fi
        elif command -v zypper >/dev/null 2>&1; then
          echo "PM zypper"
          zypper -q --non-interactive refresh >/dev/null 2>&1
          zypper -q --non-interactive lu 2>/dev/null | awk -F'|' 'NF>=6 && $1 ~ /v/ {gsub(/ /,"",$3); gsub(/ /,"",$4); gsub(/ /,"",$5); print "ZYP "$3" "$4" "$5}'
          zypper -q --non-interactive lp -g security 2>/dev/null | awk -F'|' 'NF>=5 && $1 !~ /Repository/ && $1 !~ /---/ {print "ZSEC"}'
          zypper -q needs-rebooting >/dev/null 2>&1; [ $? -eq 102 ] && echo REBOOT
        else
          echo "PM unbekannt"
        fi
        . /etc/os-release 2>/dev/null
        case "$ID" in
          debian|raspbian)
            NEW=$(python3 -c 'import urllib.request,re;t=urllib.request.urlopen("http://deb.debian.org/debian/dists/stable/Release",timeout=15).read(4000).decode();v=re.search(r"^Version: (\S+)",t,re.M);c=re.search(r"^Codename: (\S+)",t,re.M);print((v.group(1).split(".")[0] if v else "")+" "+(c.group(1) if c else ""))' 2>/dev/null)
            echo "REL $ID|$VERSION_ID|$VERSION_CODENAME|$NEW" ;;
          ubuntu)
            NEW=$(do-release-upgrade -c 2>/dev/null | sed -n "s/^New release '\(.*\)' available.*/\1/p")
            echo "REL ubuntu|$VERSION_ID|$VERSION_CODENAME|$NEW" ;;
          *)
            echo "REL $ID|$VERSION_ID|$VERSION_CODENAME|" ;;
        esac
        exit 0
    - name: Updates suchen ohne Root (Linux)
      when: upd_root is failed and not (upd_root.unreachable | default(false))
      changed_when: false
      ignore_errors: true
      ansible.builtin.shell: *upd_script
- name: Windows
  hosts: windows
  gather_facts: false
  tasks:
    - name: Updates suchen (Windows)
      ignore_errors: true
      ignore_unreachable: true
      ansible.windows.win_updates:
        state: searched
        category_names: [SecurityUpdates, CriticalUpdates, UpdateRollups, Updates]
    - name: Funktionsupdates suchen (Windows)
      ignore_errors: true
      ignore_unreachable: true
      ansible.windows.win_updates:
        state: searched
        category_names: [Upgrades]
"""
UPD_TASKS = ("Updates suchen (Linux)", "Updates suchen (Windows)")
UPD_FALLBACK = "Updates suchen ohne Root (Linux)"
UPD_FEATURE = "Funktionsupdates suchen (Windows)"
DISTRO_NAMES = {"debian": "Debian", "raspbian": "Raspberry Pi OS", "ubuntu": "Ubuntu"}


def parse_release(text):
    """REL-Zeile -> {"cur": "Debian 12 (bookworm)", "new": "Debian 13 (trixie)" oder ""}."""
    m = re.search(r"^REL ([^|]*)\|([^|]*)\|([^|]*)\|(.*)$", text, re.M)
    if not m:
        return None
    did, ver, code, new = (x.strip() for x in m.groups())
    name = DISTRO_NAMES.get(did, did.capitalize())
    cur = f"{name} {ver}" + (f" ({code})" if code else "")
    newer = ""
    if did in ("debian", "raspbian") and new:
        nv, _, ncode = new.partition(" ")
        try:
            if int(nv) > int(ver.split(".")[0]):
                newer = f"Debian {nv}" + (f" ({ncode})" if ncode else "")
        except ValueError:
            pass
    elif did == "ubuntu" and new:
        newer = f"Ubuntu {new}"
    return {"cur": cur, "new": newer}
UPD_MAX_ITEMS = 400


def parse_linux_updates(text):
    items, rpm_sec, zsec, reboot, pm, warn = [], [], 0, False, "", []
    for line in text.splitlines():
        line = line.rstrip()
        if line.startswith("PM "):
            pm = line[3:].strip()
        elif line == "REBOOT":
            reboot = True
        elif line.startswith("WARN "):
            warn.append(line[5:])
        elif line.startswith("APT Inst "):
            m = re.match(r"APT Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.*?)\)", line)
            if m:
                items.append({"name": m[1], "from": m[2] or "neu", "to": m[3], "sec": "security" in m[4].lower()})
        elif line.startswith("RPM "):
            parts = line.split()
            if len(parts) >= 3:
                items.append({"name": parts[1].rsplit(".", 1)[0], "from": "", "to": parts[2], "sec": False})
        elif line.startswith("SEC "):
            rpm_sec.append(line[4:])
        elif line.startswith("ZYP "):
            parts = line.split()
            if len(parts) >= 4:
                items.append({"name": parts[1], "from": parts[2], "to": parts[3], "sec": False})
        elif line == "ZSEC":
            zsec += 1
    for it in items:  # dnf: Sicherheits-Updates kommen als NEVRA-Liste ("openssl-libs-1:3.0.7-27.el9.x86_64")
        if not it["sec"] and any(x.startswith(it["name"] + "-") for x in rpm_sec):
            it["sec"] = True
    security = max(sum(1 for x in items if x["sec"]), zsec)
    return {"pm": pm, "items": items, "count": len(items), "security": security, "reboot": reboot, "warn": " ".join(warn)}


def parse_windows_updates(res):
    items = []
    for u in (res.get("updates") or {}).values():
        kb = u.get("kb") or []
        cats = u.get("categories") or []
        items.append({"name": u.get("title", "?"), "from": "", "to": ("KB" + str(kb[0])) if kb else "",
                      "sec": any("security" in c.lower() or "sicherheit" in c.lower() for c in cats)})
    count = res.get("found_update_count", len(items))
    return {"pm": "Windows Update", "items": items, "count": count, "security": sum(1 for x in items if x["sec"]),
            "reboot": bool(res.get("reboot_required")), "warn": ""}


def updates_job(rid, names):
    """Updates suchen (installiert nichts); Ergebnis je Maschine in status.json -> upd."""
    inv = write_inventory()
    fd, pb = tempfile.mkstemp(prefix="upd-", suffix=".yml")
    with os.fdopen(fd, "w") as f:
        f.write(UPD_CHECK_PB)
    log = open(p("runs", rid + ".log"), "w")
    ok_all = True
    try:
        log.write("$ Updates prüfen (nur suchen, nichts installieren): " + ", ".join(names) + "\n\n")
        log.flush()
        cmd = ["ansible-playbook", "-i", inv, pb, "--limit", ",".join(names), "--forks", "10"]
        r = subprocess.run(cmd, capture_output=True, text=True, env=env_json(), timeout=3600)
        try:
            out = json.loads(r.stdout[r.stdout.index("{"):])
        except ValueError:
            out = {}
            log.write(r.stdout[-5000:] + "\n" + r.stderr[-5000:] + "\n")
        res, fallback, feature = {}, {}, {}
        for play in out.get("plays", []):
            for t in play.get("tasks", []):
                tname = t.get("task", {}).get("name")
                if tname in UPD_TASKS:
                    res.update(t.get("hosts", {}))
                elif tname == UPD_FALLBACK:
                    fallback.update({k: v for k, v in t.get("hosts", {}).items() if not v.get("skipped")})
                elif tname == UPD_FEATURE:
                    feature.update(t.get("hosts", {}))
        with LOCK:
            st = load("status.json", {})
            for n in names:
                s = st.setdefault(n, {})
                prev = s.get("upd") or {}
                hr = res.get(n)
                root_err = ""
                fb = fallback.get(n)
                if hr is not None and hr.get("failed") and fb and not fb.get("failed"):
                    # Root-Rechte (sudo/su) fehlgeschlagen, Pruefung ohne Root hat geklappt
                    root_err = explain((hr.get("module_stdout") or "") + " " + (hr.get("msg") or ""))
                    hr = fb
                if hr is None:
                    u = {"ok": False, "msg": "keine Antwort von Ansible"}
                elif hr.get("unreachable") or hr.get("failed"):
                    u = {"ok": False, "msg": explain(" ".join(x for x in (hr.get("module_stdout"), hr.get("msg"), hr.get("stderr"),
                                                                          hr.get("module_stderr")) if x))}
                elif "found_update_count" in hr or "updates" in hr:
                    u = {"ok": True, **parse_windows_updates(hr)}
                    fr = feature.get(n) or {}
                    titles = [x.get("title", "") for x in (fr.get("updates") or {}).values()]
                    u["release"] = {"cur": "", "new": titles[0] if titles else ""}
                else:
                    u = {"ok": True, **parse_linux_updates(hr.get("stdout", "")), "release": parse_release(hr.get("stdout", ""))}
                    if u["pm"] in ("", "unbekannt"):
                        u = {"ok": False, "msg": "Paketverwaltung nicht erkannt (unterstützt: apt, dnf/yum, zypper)"}
                    elif root_err:
                        u["warn"] = ("Ohne Root-Rechte geprüft (" + root_err[:160] + ") – Paketlisten evtl. nicht aktuell. "
                                     "Root-Passwort im Zugangsprofil prüfen.")
                u["time"] = now()
                if u["ok"]:
                    u["items"] = u["items"][:UPD_MAX_ITEMS]
                    s["upd"] = u
                    line = "aktuell" if not u["count"] else f'{u["count"]} Updates, davon {u["security"]} Sicherheit'
                    log.write(f'{n}: {line}{" – Neustart nötig" if u["reboot"] else ""}\n')
                else:
                    ok_all = False
                    if prev.get("ok") and hr is not None and hr.get("unreachable"):
                        # nachts ausgeschaltet: letztes Ergebnis behalten, nur vermerken
                        prev["stale"] = f'{u["time"]}: nicht erreichbar'
                        s["upd"] = prev
                    else:
                        s["upd"] = u
                    log.write(f'{n}: FEHLER - {u["msg"]}\n')
            save("status.json", st)
    except Exception as ex:  # noqa: BLE001
        log.write(f"Fehler: {ex}\n")
        ok_all = False
    finally:
        log.close()
        os.unlink(inv)
        os.unlink(pb)
        finish_run(rid, "ok" if ok_all else "Fehler")


REBOOT_PB = r"""
# Eine Maschine neu starten und warten, bis sie VOLLSTAENDIG wieder laeuft (sonst Fehler -> Kette bricht ab).
- name: Linux neu starten
  hosts: linux
  gather_facts: false
  tasks:
    - name: Neustart (Linux)
      become: "{{ ansible_become_method is defined }}"
      ansible.builtin.reboot:
        reboot_timeout: 900
        msg: "Neustart durch Ansible-UI"
    - name: Warten, bis das System vollstaendig gestartet ist (systemctl is-system-running)
      ansible.builtin.command: systemctl is-system-running
      register: sysstate
      changed_when: false
      failed_when: false
      until: sysstate.stdout in ['running', 'degraded'] or sysstate.rc == 127 or 'not found' in (sysstate.stderr | default(''))
      retries: 60
      delay: 10
    - name: System nicht vollstaendig gestartet
      ansible.builtin.fail:
        msg: "Systemzustand nach 10 Minuten: {{ sysstate.stdout | default('?') }} - Kette abgebrochen."
      when: not (sysstate.stdout in ['running', 'degraded'] or sysstate.rc == 127 or 'not found' in (sysstate.stderr | default('')))
    - name: Ausgefallene Dienste (System laeuft, aber "degraded")
      ansible.builtin.command: systemctl --failed --no-legend --no-pager
      register: failedunits
      changed_when: false
      when: sysstate.stdout == 'degraded'
    - name: Hinweis
      ansible.builtin.debug:
        msg: "ACHTUNG degraded - ausgefallene Dienste: {{ failedunits.stdout_lines | default([]) }}"
      when: sysstate.stdout == 'degraded'
- name: Windows neu starten
  hosts: windows
  gather_facts: false
  tasks:
    - name: Neustart (Windows)
      ansible.windows.win_reboot:
        reboot_timeout: 1800
        post_reboot_delay: 30
        msg: "Neustart durch Ansible-UI"
    - name: Warten, bis keine Dienste mehr starten
      ansible.windows.win_shell: "@(Get-Service | Where-Object { $_.Status -like '*Pending' }).Count"
      register: pend
      changed_when: false
      until: (pend.stdout | default('x') | trim) == '0'
      retries: 60
      delay: 10
    - name: Automatische Dienste, die nicht laufen (nur Info)
      ansible.windows.win_shell: "Get-CimInstance Win32_Service -Filter \"StartMode='Auto' AND State<>'Running'\" | Select-Object -ExpandProperty Name"
      register: autostopped
      changed_when: false
      failed_when: false
    - name: Hinweis
      ansible.builtin.debug:
        msg: "Automatische Dienste nicht gestartet (oft normal): {{ autostopped.stdout_lines | default([]) }}"
"""


DIST_UPGRADE_PB = r"""
- name: Distributions-Upgrade
  hosts: linux
  gather_facts: true
  become: "{{ ansible_become_method is defined }}"
  vars:
    debian_new: ""
    # Fester Pfad statt der erkannten Version (z.B. /usr/bin/python3.10): das Release-Upgrade entfernt
    # genau diesen Python, danach scheiterte jede Abfrage und die Warteschleife lief stundenlang weiter.
    ansible_python_interpreter: /usr/bin/python3
  environment:
    DEBIAN_FRONTEND: noninteractive
    APT_LISTCHANGES_FRONTEND: none
  tasks:
    - name: Vorab-Pruefung - kein Proxmox
      ansible.builtin.stat:
        path: /etc/pve
      register: pve
    - name: Abbruch bei Proxmox
      ansible.builtin.fail:
        msg: "Proxmox-Host - Upgrade nur mit den Proxmox-Anleitungen (pveXtoY), nicht hier."
      when: pve.stat.exists or 'pve' in ansible_facts['kernel']
    - name: Vorab-Pruefung - freier Platz auf /
      ansible.builtin.assert:
        that: (ansible_facts['mounts'] | selectattr('mount', 'equalto', '/') | map(attribute='size_available') | first) > 4294967296
        fail_msg: "Weniger als 4 GB frei auf / - Upgrade abgebrochen."
    - name: Sicherung von /etc/apt
      ansible.builtin.shell: "cp -a /etc/apt /root/apt-backup-$(date +%Y%m%d-%H%M%S)"
    - name: Aktuellen Stand komplett aktualisieren
      ansible.builtin.apt:
        update_cache: true
        upgrade: dist
        autoremove: true
        dpkg_options: force-confdef,force-confold
    - name: Neustart noetig vor dem Upgrade?
      ansible.builtin.stat:
        path: /var/run/reboot-required
      register: rr
    - name: Neustart vor dem Upgrade
      ansible.builtin.reboot:
        reboot_timeout: 900
      when: rr.stat.exists
    # ---- Ubuntu
    - name: Upgrade-Werkzeug (Ubuntu)
      ansible.builtin.apt:
        name: ubuntu-release-upgrader-core
        state: present
      when: ansible_facts['distribution'] == 'Ubuntu'
    # Start im Hintergrund (poll: 0) und eigene async_status-Abfragen: die eingebaute
    # Abfrageschleife (poll: 30) blieb bei einem Ubuntu-Host trotz fertigem Job auf "nicht fertig" haengen.
    - name: do-release-upgrade starten (Ubuntu, laeuft auf dem Host weiter, auch wenn die Verbindung abreisst)
      ansible.builtin.command: do-release-upgrade -f DistUpgradeViewNonInteractive
      async: 14400
      poll: 0
      register: dru_job
      when: ansible_facts['distribution'] == 'Ubuntu'
    # ansible_ssh_retries: kurzen SSH-Ausfall (Neustart von openssh-server) ueberstehen statt abzubrechen.
    # Scheitert die Abfrage selbst (module_stderr/exception), endet die Schleife sofort mit Fehler statt still weiterzuwarten.
    - name: Warten bis do-release-upgrade fertig ist (Ubuntu)
      ansible.builtin.async_status:
        jid: "{{ dru_job.ansible_job_id }}"
      register: dru
      vars:
        ansible_ssh_retries: 12
      until: (dru.finished | default(false)) or dru.module_stderr is defined or dru.exception is defined
      retries: 480
      delay: 30
      failed_when: not (dru.finished | default(false)) or (dru.rc | default(1)) != 0
      when: ansible_facts['distribution'] == 'Ubuntu'
    # ---- Debian / Raspberry Pi OS
    - name: Offizielle Debian-/Raspberry-Pi-Quellen auf {{ debian_new }} umstellen (fremde Quellen bleiben)
      ansible.builtin.shell: |
        set -e
        OLD={{ ansible_facts['distribution_release'] }}
        for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
          [ -f "$f" ] || continue
          sed -i -E "/debian\.org|raspberrypi\.(com|org)/ s/\b${OLD}\b/{{ debian_new }}/g" "$f"
          case "$f" in *.sources)
            grep -qE "debian\.org|raspberrypi\.(com|org)" "$f" && sed -i -E "/^Suites:/ s/\b${OLD}(-security|-updates|-backports)?\b/{{ debian_new }}\1/g" "$f" ;;
          esac
        done
        grep -rhE "^(deb |Suites:)" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null || true
      when: ansible_facts['distribution'] != 'Ubuntu' and debian_new | length > 0
    - name: full-upgrade auf {{ debian_new }} (laeuft auf dem Host weiter, auch wenn die Verbindung abreisst)
      ansible.builtin.shell: |
        apt-get update && apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade && apt-get -y autoremove
      async: 14400
      poll: 0
      register: dfu_job
      when: ansible_facts['distribution'] != 'Ubuntu' and debian_new | length > 0
    - name: Warten bis full-upgrade fertig ist (Debian)
      ansible.builtin.async_status:
        jid: "{{ dfu_job.ansible_job_id }}"
      register: dfu
      vars:
        ansible_ssh_retries: 12
      until: (dfu.finished | default(false)) or dfu.module_stderr is defined or dfu.exception is defined
      retries: 480
      delay: 30
      failed_when: not (dfu.finished | default(false)) or (dfu.rc | default(1)) != 0
      when: ansible_facts['distribution'] != 'Ubuntu' and debian_new | length > 0
    - name: Neustart nach dem Upgrade
      ansible.builtin.reboot:
        reboot_timeout: 1200
    - name: Neue Version
      ansible.builtin.shell: ". /etc/os-release; echo $PRETTY_NAME"
      register: osr
      changed_when: false
    - name: Ergebnis
      ansible.builtin.debug:
        msg: "Jetzt: {{ osr.stdout }}"
"""


def upgrade_job(rid, name, debian_new):
    """Distributions-Upgrade einer Maschine, danach Fakten + Updates neu holen."""
    inv = write_inventory()
    fd, pb = tempfile.mkstemp(prefix="dist-", suffix=".yml")
    with os.fdopen(fd, "w") as f:
        f.write(DIST_UPGRADE_PB)
    try:
        with open(p("runs", rid + ".log"), "w") as log:
            log.write(f"$ Distributions-Upgrade {name}" + (f" -> {debian_new}" if debian_new else "") + "\n\n")
            log.flush()
            r = subprocess.run(["ansible-playbook", "-i", inv, pb, "--limit", name, "-e", json.dumps({"debian_new": debian_new})],
                               stdout=log, stderr=subprocess.STDOUT, text=True, timeout=21600)
        finish_run(rid, "ok" if r.returncode == 0 else f"Fehler (rc {r.returncode})")
    except Exception as ex:  # noqa: BLE001
        with open(p("runs", rid + ".log"), "a") as log:
            log.write(f"\nFehler: {ex}\n")
        finish_run(rid, "Fehler")
    finally:
        os.unlink(inv)
        os.unlink(pb)
    adhoc_job(new_run("facts", name, f"Info Device nach Upgrade: {name}"), "facts", [name])
    updates_job(new_run("updates", name, f"Updates prüfen nach Upgrade: {name}"), [name])


RECAP_RE = re.compile(r"^(\S+)\s*:\s*ok=(\d+)\s+changed=\d+\s+unreachable=(\d+)\s+failed=(\d+)", re.M)


def reboot_job(rid, stages, wait_min=0):
    """Neustart in Stufen: alle Maschinen einer Stufe gleichzeitig (Linux und Windows parallel), die naechste Stufe erst,
    wenn ALLE der vorigen vollstaendig wieder laufen (Playbook ohne ignore_errors). Scheitert eine, bricht die Kette ab."""
    if stages and isinstance(stages[0], str):  # alte Aufrufe: flache Liste = eine Maschine je Stufe
        stages = [[n] for n in stages]
    inv = write_inventory()
    fd, pb = tempfile.mkstemp(prefix="reboot-", suffix=".yml")
    with os.fdopen(fd, "w") as f:
        f.write(REBOOT_PB)
    hmap = {h["name"]: h for h in hosts()}
    disp = {n: display_name(h) for n, h in hmap.items()}
    dn = lambda xs: ", ".join(disp.get(x, x) for x in xs)  # noqa: E731
    done, failed = [], []
    try:
        with open(p("runs", rid + ".log"), "w") as log:
            log.write("Neustart in Stufen: " + " → ".join(f"[{dn(st)}]" for st in stages)
                      + (f"\nZusätzliche Wartezeit zwischen den Stufen: {wait_min} min" if wait_min else "") + "\n")
            log.flush()
            for i, stage in enumerate(stages, 1):
                log.write(f"\n===== Stufe {i}/{len(stages)}: {dn(stage)} – {now()} =====\n")
                log.flush()
                parts = {}

                def one(group, names):
                    fd2, tmp = tempfile.mkstemp(prefix="rb-", suffix=".log")
                    with os.fdopen(fd2, "w") as out:
                        r = subprocess.run(["ansible-playbook", "-i", inv, pb, "--limit", ",".join(names), "--forks", "20"],
                                           stdout=out, stderr=subprocess.STDOUT, text=True, timeout=5400)
                    with open(tmp) as f:
                        parts[group] = (r.returncode, f.read())
                    os.unlink(tmp)
                by_group = {}
                for n in stage:
                    by_group.setdefault(hmap.get(n, {}).get("group", "linux"), []).append(n)
                ths = [threading.Thread(target=one, args=(g, ns)) for g, ns in by_group.items()]
                for t in ths:
                    t.start()
                for t in ths:
                    t.join()
                good = set()
                for g, (rc, text) in parts.items():
                    log.write(f"\n--- {g}: {dn(by_group[g])} ---\n{text}")
                    for m in RECAP_RE.finditer(text):
                        if int(m[2]) > 0 and m[3] == "0" and m[4] == "0":
                            good.add(m[1])
                bad = [n for n in stage if n not in good]
                done += [n for n in stage if n in good]
                if bad:
                    failed = bad
                    rest = [n for st in stages[i:] for n in st]
                    log.write(f"\n✗ Nicht vollständig zurückgekommen: {dn(bad)} – Kette abgebrochen."
                              + (f"\n  NICHT neu gestartet: {dn(rest)}" if rest else "") + "\n")
                    break
                log.write(f"\n✓ Stufe {i} läuft wieder vollständig: {dn(stage)} ({now()}).\n")
                if wait_min and i < len(stages):
                    log.write(f"  warte noch {wait_min} min …\n")
                    log.flush()
                    time.sleep(wait_min * 60)
            total = sum(len(st) for st in stages)
            log.write("\nFertig: " + (f"{len(done)} von {total} neu gestartet." if failed else f"alle {total} neu gestartet.") + "\n")
        finish_run(rid, "Fehler" if failed else "ok")
    except Exception as ex:  # noqa: BLE001
        with open(p("runs", rid + ".log"), "a") as log:
            log.write(f"\nFehler: {ex}\n")
        finish_run(rid, "Fehler")
    finally:
        os.unlink(inv)
        os.unlink(pb)
    again = done + failed
    if again:
        adhoc_job(new_run("facts", ",".join(again), "Info Device nach Neustart: " + ", ".join(again), again), "facts", again)
        updates_job(new_run("updates", ",".join(again), "Updates prüfen nach Neustart: " + ", ".join(again), again), again)


def settings_data():
    s = load("settings.json", {})
    s.setdefault("upd_nightly", True)
    s.setdefault("upd_time", "04:00")
    return s


def nightly_loop():
    """Naechtliche Update-Pruefung aller aktiven Maschinen (einmal pro Tag zur eingestellten Uhrzeit)."""
    while True:
        time.sleep(60)
        try:
            s = settings_data()
            today = datetime.date.today().isoformat()
            hh, mm = map(int, s["upd_time"].split(":"))
            due = datetime.datetime.now().replace(hour=hh, minute=mm, second=0, microsecond=0)
            # nur im Fenster bis 3 h nach der Pruefzeit - kein Nachholen beim Start am Tag
            if not s["upd_nightly"] or s.get("upd_last") == today or not (due <= datetime.datetime.now() < due + datetime.timedelta(hours=3)):
                continue
            s["upd_last"] = today
            save("settings.json", s)
            names = [h["name"] for h in hosts() if h.get("enabled", True) and h.get("address")]
            if names:
                adhoc_job(new_run("facts", "all", "Info Device (nächtlich): alle"), "facts", names)
                updates_job(new_run("updates", "all", "Updates prüfen (nächtlich): alle"), names)
        except Exception:  # noqa: BLE001
            pass


def playbook_job(rid, playbook, target, check):
    inv = write_inventory()
    try:
        with open(p("runs", rid + ".log"), "w") as log:
            cmd = ["ansible-playbook", "-i", inv, p("playbooks", playbook), "--limit", target]
            if check:
                cmd.append("--check")
            log.write("$ ansible-playbook " + playbook + " --limit " + target + (" --check" if check else "") + "\n\n")
            log.flush()
            r = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, text=True, timeout=7200)
        finish_run(rid, "ok" if r.returncode == 0 else f"Fehler (rc {r.returncode})")
        if playbook.startswith("updates-installieren") and not check:
            # Spalte "Updates" gleich aktualisieren
            tset = set(target.split(","))
            names = [h["name"] for h in hosts() if h.get("enabled", True) and h.get("address")
                     and (tset & {"all", h["group"], h["name"]})]
            if names:
                adhoc_job(new_run("facts", target, f"Info Device nach Installation: {target}"), "facts", names)
                updates_job(new_run("updates", target, f"Updates prüfen nach Installation: {target}"), names)
    except Exception as ex:  # noqa: BLE001
        with open(p("runs", rid + ".log"), "a") as log:
            log.write(f"\nFehler: {ex}\n")
        finish_run(rid, "Fehler")
    finally:
        os.unlink(inv)


def start(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


# ---------------------------------------------------------------- Web
def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        if not is_admin():
            cu = cur_user()
            if not cu:  # Benutzer wurde geloescht
                session.clear()
                return redirect(url_for("login"))
            if cu.get("must_change") and cu.get("source") != "ad" and request.endpoint not in ("own_password", "logout"):
                return redirect(url_for("own_password"))
        if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
            abort(400)
        return fn(*a, **kw)
    return wrapper


@app.context_processor
def ctx():
    if not session.get("user"):
        return {"csrf": "", "groups": GROUPS, "locations": [], "admin": False, "can_run": False, "can": {k: False for k in ACTIONS}}
    return {"csrf": session.get("csrf", ""), "groups": GROUPS, "locations": visible_locs(), "admin": is_admin(),
            "can_run": can_run(), "can": can_map()}


def check_admin(pw):
    """Gehashtes Passwort aus auth.json; ohne Datei gilt das Start-Passwort aus ADMIN_PASSWORD."""
    auth = load("auth.json", {})
    if auth.get("hash"):
        return check_password_hash(auth["hash"], pw)
    return bool(ADMIN_PASSWORD) and secrets.compare_digest(pw, ADMIN_PASSWORD)


# ---------------------------------------------------------------- Benutzer und Rechte
# users.json: [{"name", "hash", "can_run": bool, "perms": {"<Standort>": "*" | ["<Maschine>", ...]}, "created", "changed"}]
# Der Admin (ADMIN_USER) steht nicht in users.json und sieht/darf alles.
def users_data():
    return load("users.json", [])


def find_user(name):
    return next((u for u in users_data() if u["name"] == name), None)


def is_admin():
    return session.get("user") == ADMIN_USER and session.get("role", "admin") == "admin"


def cur_user():
    return None if is_admin() else find_user(session.get("user", ""))


# Rechte fuer Aktionen (pro Benutzer und/oder Benutzergruppe; wirksam = Vereinigung)
ACTIONS = {"ping": "Ping", "facts": "Info Device", "upd_check": "Updates prüfen und Update Check",
           "upd_install": "Updates installieren", "plan": "Updates / Neustarts planen", "reboot": "Neustart"}


def groups_data():
    """groups.json: [{"id", "name", "actions": [...], "perms": {...}, "created", "changed"}]"""
    return load("groups.json", [])


def user_groups(u):
    ids = set(u.get("groups") or [])
    return [g for g in groups_data() if g["id"] in ids]


def own_actions(u):
    if "actions" in u:
        return set(u.get("actions") or [])
    return set(ACTIONS) if u.get("can_run") else set()  # aeltere Eintraege: "darf bedienen"


def eff_actions(u):
    out = own_actions(u)
    for g in user_groups(u):
        out |= set(g.get("actions") or [])
    return out & set(ACTIONS)


def perm_allows(perms, h):
    v = (perms or {}).get(h.get("location") or "")
    return v == "*" or v == "group:" + h.get("group", "") or (isinstance(v, list) and h["name"] in v)


def can_see(h, u=None):
    if u is None:
        if is_admin():
            return True
        u = cur_user()
    if not u:
        return False
    return perm_allows(u.get("perms"), h) or any(perm_allows(g.get("perms"), h) for g in user_groups(u))


def visible_hosts():
    hs = hosts()
    if is_admin():
        return hs
    u = cur_user()
    return [h for h in hs if can_see(h, u)]


def visible_locs():
    if is_admin():
        return loc_names()
    names = {h.get("location") or "" for h in visible_hosts()}
    return [x for x in loc_names() if x in names]


def can_do(action):
    return is_admin() or action in eff_actions(cur_user() or {})


def can_map():
    if is_admin():
        return {k: True for k in ACTIONS}
    eff = eff_actions(cur_user() or {})
    return {k: k in eff for k in ACTIONS}


def can_run():
    """Irgendeine Aktion erlaubt (Grundvoraussetzung fuer die Aktions-Routen; Details prueft can_do)."""
    return is_admin() or bool(eff_actions(cur_user() or {}))


def run_hosts(r):
    """Maschinen eines Laufs: gespeichert (neu) oder aus dem Ziel abgeleitet (Name, Namensliste, Gruppe, all)."""
    if r.get("hosts"):
        return set(r["hosts"])
    hs = hosts()
    out = set()
    for t in str(r.get("target", "")).split(","):
        t = t.strip()
        if t == "all":
            return {h["name"] for h in hs}
        if t in GROUPS:
            out |= {h["name"] for h in hs if h["group"] == t}
        elif any(h["name"] == t for h in hs):
            out.add(t)
    return out


def can_see_run(r):
    if is_admin():
        return True
    names = run_hosts(r)
    vis = {h["name"] for h in visible_hosts()}
    return bool(names) and names <= vis


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not is_admin():
            abort(403)
        return fn(*a, **kw)
    return login_required(wrapper)


def run_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not can_run():
            abort(403)
        return fn(*a, **kw)
    return login_required(wrapper)


def rename_in_perms(kind, old, new):
    """Standort/Maschine umbenannt (new) oder geloescht (new=None): Rechte der Benutzer und Gruppen nachziehen."""
    for fn in ("users.json", "groups.json"):
        with LOCK:
            items = load(fn, [])
            changed = False
            for u in items:
                pm = u.get("perms") or {}
                if kind == "location" and old in pm:
                    v = pm.pop(old)
                    if new is not None:
                        pm[new] = v
                    changed = True
                elif kind == "host":
                    for k, v in pm.items():
                        if isinstance(v, list) and old in v:
                            pm[k] = [x for x in v if x != old] + ([new] if new else [])
                            changed = True
                u["perms"] = pm
            if changed:
                save(fn, items, 0o600)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        un, pw = request.form.get("user", "").strip(), request.form.get("password", "")
        u = find_login(un) if un != ADMIN_USER else None
        ok = False
        if u and pw:
            if u.get("source") == "ad":
                ok, why = ad_authenticate(u, pw)
                if not ok and why:
                    app.logger.warning("AD-Anmeldung %s: %s", u["name"], why)
            else:
                ok = bool(u.get("hash")) and check_password_hash(u["hash"], pw)
        if ok:
            session.clear()
            session.update(user=u["name"], role="user", csrf=secrets.token_hex(16))
            session.permanent = True
            if u.get("must_change") and u.get("source") != "ad":
                flash("Bitte jetzt ein eigenes Passwort festlegen.", "ok")
                return redirect(url_for("own_password"))
            nxt = request.args.get("next", "/")
            return redirect(nxt if nxt.startswith("/") else "/")
        if un == ADMIN_USER and check_admin(pw):
            session.clear()
            session.update(user=ADMIN_USER, role="admin", csrf=secrets.token_hex(16))
            session.permanent = True
            nxt = request.args.get("next", "/")
            return redirect(nxt if nxt.startswith("/") else "/")
        flash("Benutzer oder Passwort falsch.", "err")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    st = load("status.json", {})
    sec = profiles_data()
    rows = []
    for h in visible_hosts():
        pr = profile_for(h, sec)
        rows.append({**h, "st": st.get(h["name"], {}), "sum": summary(facts_of(h["name"])), "addrs": addr_list(h),
                     "prof": pr["name"] if pr else "kein Profil", "prof_own": bool(h.get("profile"))})
    grp = request.args.get("gruppe", "")
    loc = request.args.get("standort", "")
    stat = request.args.get("status", "")
    updf = request.args.get("updates", "")
    for r in rows:
        r["skey"] = status_key(r, r["st"])
        r["ukeys"] = upd_keys(r, r["st"])
    counts = {x: sum(1 for r in rows if r.get("location") == x and (not grp or r["group"] == grp)
                     and (not stat or r["skey"] == stat) and (not updf or updf in r["ukeys"])) for x in visible_locs()}
    if grp:
        rows = [r for r in rows if r["group"] == grp]
    if loc:
        rows = [r for r in rows if r.get("location") == loc]
    scounts = {k: sum(1 for r in rows if r["skey"] == k and (not updf or updf in r["ukeys"])) for k in STATUS_LABELS}
    if stat:
        rows = [r for r in rows if r["skey"] == stat]
    ucounts = {k: sum(1 for r in rows if k in r["ukeys"]) for k in UPD_LABELS}
    if updf:
        rows = [r for r in rows if updf in r["ukeys"]]
    running = [r for r in load("runs/index.json", []) if r["status"] == "laeuft" and can_see_run(r)]
    allruns = load("runs/index.json", [])
    for r in rows:  # letzter Update-/Check-Lauf der Maschine: Fehler sichtbar lassen, bis ein spaeterer Lauf klappt
        last = next((x for x in allruns if x["kind"] in ("playbook", "upgrade", "reboot") and x["status"] != "laeuft"
                     and set(str(x.get("target", "")).split(",")) & {r["name"], r["group"], "all"}), None)
        u = r["st"].get("upd") or {}
        later = u.get("ok") and u.get("time", "") > (last or {}).get("end", "")
        if (last or {}).get("kind") == "upgrade":  # Upgrade erledigt = keine neuere Version mehr
            settled = later and not (u.get("release") or {}).get("new")
        else:  # Update erledigt = danach "aktuell" geprueft
            settled = later and not u.get("count")
        if last and last["status"] not in ("ok",) and not settled:
            r["lastfail"] = {"id": last["id"], "what": {"upgrade": "Upgrade", "reboot": "Neustart"}.get(
                                 last["kind"], "Update Check" if "Probelauf" in last["title"] else "Update"),
                             "time": (last.get("end") or last["start"])[11:16], "why": run_reason(last["id"], r["name"]),
                             "verb": "abgebrochen" if last["status"] == "abgebrochen" else "fehlgeschlagen"}
    for r in rows:  # laufende Aktion je Maschine (Ziel = Name, Namensliste, Gruppe oder "all")
        for x in running:
            t = set(str(x.get("target", "")).split(","))
            if t & {r["name"], r["group"], "all"}:
                if x["kind"] == "playbook":
                    what = "Update Check läuft" if "Probelauf" in x["title"] else "Update läuft"
                else:
                    what = {"updates": "Prüfung läuft", "ping": "Ping läuft", "facts": "Info Device läuft", "reboot": "Neustart läuft", "upgrade": "Upgrade läuft"}.get(x["kind"], "läuft")
                r["run"] = {"id": x["id"], "what": what, "start": x["start"]}
                break
    return render_template("index.html", rows=rows, grp=grp, loc=loc, stat=stat, counts=counts, scounts=scounts,
                           slabels=STATUS_LABELS, updf=updf, ucounts=ucounts, ulabels=UPD_LABELS, running=running, pbs=set(playbooks()),
                           n_check=sum(1 for r in rows if r.get("enabled", True) and r.get("address")),
                           n_reboot=sum(1 for r in rows if r.get("enabled", True) and r.get("address") and not r.get("no_mass")
                                        and (r["st"].get("upd") or {}).get("reboot")),
                           n_upd=sum(1 for r in rows if r.get("enabled", True) and r.get("address") and not r.get("no_mass")
                                     and (r["st"].get("upd") or {}).get("ok") and r["st"]["upd"].get("count")),
                           reboot_rows=[r for r in rows if r.get("enabled", True) and r.get("address") and (r["st"].get("upd") or {}).get("reboot")],
                           upd_rows=[r for r in rows if r.get("enabled", True) and r.get("address")
                                     and (r["st"].get("upd") or {}).get("ok") and r["st"]["upd"].get("count")],
                           plans=sorted([x for x in load("schedule.json", []) if is_admin()
                                         or set(x["names"]) <= {h["name"] for h in visible_hosts()}], key=lambda x: x["when"]),
                           now_min=datetime.datetime.now().strftime("%Y-%m-%dT%H:%M"),
                           disp={h["name"]: display_name(h) for h in hosts()})


STATUS_LABELS = {"ok": "erreichbar", "fehler": "Fehler", "unbekannt": "unbekannt", "inaktiv": "inaktiv"}
UPD_LABELS = {"offen": "Updates verfügbar", "sicherheit": "mit Sicherheits-Updates", "neustart": "Neustart nötig",
              "aktuell": "aktuell", "version": "Neue Version verfügbar", "fehler": "Fehler / nicht geprüft"}


def upd_keys(h, st):
    """Update-Filterkategorien einer Maschine."""
    u = (st or {}).get("upd") or {}
    if not h.get("enabled", True) or not h.get("address"):
        return set()
    if not u.get("ok"):
        return {"fehler"}
    k = {"offen"} if u.get("count") else {"aktuell"}
    if u.get("security"):
        k.add("sicherheit")
    if u.get("reboot"):
        k.add("neustart")
    if (u.get("release") or {}).get("new"):
        k.add("version")
    return k


def status_key(h, st):
    if not h.get("enabled", True):
        return "inaktiv"
    if not st.get("ping_time"):
        return "unbekannt"
    return "ok" if st.get("ping_ok") else "fehler"


def run_reason(rid, name):
    """Kurzer Grund aus dem Protokoll eines Laufs fuer eine Maschine (fatal/unreachable-Zeile)."""
    try:
        with open(p("runs", rid + ".log")) as f:
            text = f.read()[-60000:]
    except OSError:
        return ""
    line = None
    for mm in re.finditer(r"(?:fatal|unreachable): \[" + re.escape(name) + r"\].*", text):
        line = text[mm.start():mm.start() + 3000]  # Ausgabe kann mehrzeilig sein ("FAILED! => {" ...)
    if line:
        parts = [x for k in ("module_stdout", "msg") for x in re.findall(r'"' + k + r'": "(.*?)(?<!\\)"', line)]
        return explain(" ".join(x.replace("\\r", " ").replace("\\n", " ") for x in parts) or line)[:140]
    return "abgebrochen" if "abgebrochen" in text else ""


def qs(**kw):
    """Query-String fuer die Filterknoepfe."""
    return "?" + urllib.parse.urlencode({k: v for k, v in kw.items() if v}) if any(kw.values()) else "/"


app.jinja_env.globals["qs"] = qs


@app.post("/aktion")
@run_required
def action():
    kind = request.form.get("kind")
    target = request.form.get("target", "")
    grp, loc, stat = request.form.get("gruppe", ""), request.form.get("standort", ""), request.form.get("status", "")
    updf = request.form.get("updates", "")
    if kind not in ("ping", "facts", "updates"):
        abort(400)
    if not can_do({"ping": "ping", "facts": "facts", "updates": "upd_check"}[kind]):
        abort(403)
    act = [h for h in visible_hosts() if h.get("enabled", True) and h.get("address")]
    if target and target != "all":
        names = [h["name"] for h in act if h["name"] == target or h["group"] == target]
    else:
        st = load("status.json", {})
        names = [h["name"] for h in act if (not grp or h["group"] == grp) and (not loc or h.get("location") == loc)
                 and (not stat or status_key(h, st.get(h["name"], {})) == stat)
                 and (not updf or updf in upd_keys(h, st.get(h["name"], {})))]
        target = " / ".join(x for x in (loc, grp, STATUS_LABELS.get(stat, ""), UPD_LABELS.get(updf, "")) if x) or "all"
    if not names:
        flash("Keine aktive Maschine mit Adresse ausgewaehlt.", "err")
        return redirect(request.referrer or "/")
    title = {"ping": "Ping", "facts": "Info Device", "updates": "Updates prüfen"}[kind] + ": " + (target or "alle")
    rid = new_run(kind, target or "all", title, names)
    if kind == "updates":
        start(updates_job, rid, names)
        flash(f"{title} gestartet - dauert je nach System einige Sekunden bis Minuten (Windows Update ist langsam).", "ok")
    else:
        start(adhoc_job, rid, kind, names)
        flash(f"{title} gestartet - Ergebnis in wenigen Sekunden.", "ok")
    return redirect(request.referrer or "/")


@app.post("/upgrade")
@admin_required
def upgrade_action():
    name = request.form.get("target", "")
    h = next((x for x in hosts() if x["name"] == name and x.get("enabled", True) and x.get("address")), None)
    u = (load("status.json", {}).get(name, {}).get("upd") or {})
    rel = u.get("release") or {}
    if not h or h["group"] != "linux" or not rel.get("new"):
        flash("Für diese Maschine ist kein Distributions-Upgrade verfügbar.", "err")
        return redirect(request.referrer or "/")
    if "pve" in summary(facts_of(name)).get("kernel", ""):
        flash("Proxmox-Hosts werden nicht über diesen Knopf aktualisiert.", "err")
        return redirect(request.referrer or "/")
    m = re.match(r"Debian (\d+) \((\w+)\)", rel["new"])
    debian_new = m.group(2) if m else ""
    if not rel["new"].startswith("Ubuntu") and not debian_new:
        flash("Zielversion nicht erkannt.", "err")
        return redirect(request.referrer or "/")
    rid = new_run("upgrade", name, f"Distributions-Upgrade: {display_name(h)} → {rel['new']}")
    start(upgrade_job, rid, name, debian_new)
    return redirect(url_for("run_view", rid=rid))


@app.post("/neustart")
@run_required
def reboot_action():
    """Neustart einer Maschine (target) oder aus dem Dialog: angehakte Maschinen in der gewaehlten Reihenfolge,
    sofort oder geplant."""
    target = request.form.get("target", "")
    if not can_do("reboot") or (not target and request.form.get("mode") == "plan" and not can_do("plan")):
        abort(403)
    act = {h["name"]: h for h in visible_hosts() if h.get("enabled", True) and h.get("address")}
    if target:
        names = [target] if target in act else []
        stages = [names]
        wait_min = 0
    else:
        names = list(dict.fromkeys(n for n in request.form.getlist("host") if n in act))
        def stage_of(n):
            try:
                return max(1, int(request.form.get("st_" + n) or 0))
            except ValueError:
                return 999
        stages = [[n for n in names if stage_of(n) == k] for k in sorted({stage_of(n) for n in names})]
        try:
            wait_min = max(0, min(120, int(request.form.get("wait") or 0)))
        except ValueError:
            wait_min = 0
    if not names:
        flash("Keine Maschine zum Neustarten ausgewählt.", "err")
        return redirect(request.referrer or "/")
    if not target and request.form.get("mode") == "plan":
        try:
            when = datetime.datetime.strptime(request.form.get("when", ""), "%Y-%m-%dT%H:%M")
        except ValueError:
            flash("Bitte Datum und Uhrzeit für den geplanten Neustart angeben.", "err")
            return redirect(request.referrer or "/")
        if when <= datetime.datetime.now():
            flash("Der geplante Zeitpunkt liegt in der Vergangenheit.", "err")
            return redirect(request.referrer or "/")
        with LOCK:
            plans = load("schedule.json", [])
            plans.append({"id": uuid.uuid4().hex[:8], "kind": "reboot", "when": when.strftime("%Y-%m-%d %H:%M"),
                          "names": [n for st in stages for n in st], "stages": stages, "wait": wait_min, "created": now(), "status": "geplant"})
            save("schedule.json", plans)
        flash(f"Neustart von {len(names)} Maschine(n) geplant für {when.strftime('%d.%m.%Y %H:%M')}.", "ok")
        return redirect(request.referrer or "/")
    start_reboot(stages, wait_min)
    flash(("Neustart gestartet: " + display_name(act[names[0]])) if len(names) == 1 else
          f"Neustart von {len(names)} Maschine(n) in {len(stages)} Stufe(n) gestartet – die nächste Stufe erst, wenn die vorige vollständig läuft.", "ok")
    return redirect(request.referrer or "/")


def start_reboot(stages, wait_min=0):
    if stages and isinstance(stages[0], str):
        stages = [[n] for n in stages]
    disp = {h["name"]: display_name(h) for h in hosts()}
    names = [n for st in stages for n in st]
    title = "Neustart: " + " → ".join(" + ".join(disp.get(n, n) for n in st) for st in stages)
    rid = new_run("reboot", ",".join(names), title[:200], names)
    start(reboot_job, rid, stages, wait_min)
    return rid


def launch_mass(kind, sel, label):
    """Je Gruppe ein Lauf des Update-Playbooks (kind check = Probelauf). Rueckgabe: ["linux: 3", ...]."""
    started = []
    for g in GROUPS:
        pb = f"updates-installieren-{g}.yml"
        names = [h["name"] for h in sel if h["group"] == g]
        if not names or pb not in playbooks():
            continue
        title = f"{'Update Check' if kind == 'check' else 'Update'} {g} ({label}): {len(names)} Maschine(n)"
        rid = new_run("playbook", ",".join(names), title + (" (Probelauf)" if kind == "check" else ""), names)
        start(playbook_job, rid, pb, ",".join(names), kind == "check")
        started.append(f"{g}: {len(names)}")
    return started


@app.post("/massen")
@run_required
def mass_action():
    """Check (Probelauf) oder Update fuer alle bzw. die gefilterte Auswahl; Update nur dort, wo Updates offen sind.
    Aus dem Update-Dialog (pick=1): explizit angehakte Maschinen, sofort oder geplant (when)."""
    kind = request.form.get("kind")
    if kind not in ("check", "update"):
        abort(400)
    if not can_do("upd_check" if kind == "check" else "upd_install") or \
            (kind == "update" and request.form.get("mode") == "plan" and not can_do("plan")):
        abort(403)
    grp, loc, stat = request.form.get("gruppe", ""), request.form.get("standort", ""), request.form.get("status", "")
    updf = request.form.get("updates", "")
    st = load("status.json", {})
    label = " / ".join(x for x in (loc, STATUS_LABELS.get(stat, ""), UPD_LABELS.get(updf, "")) if x) or "alle"
    if kind == "update" and request.form.get("pick"):
        picked = set(request.form.getlist("host"))
        sel = [h for h in visible_hosts() if h.get("enabled", True) and h.get("address") and h["name"] in picked]
        if not sel:
            flash("Keine Maschine angehakt.", "err")
            return redirect(request.referrer or "/")
        if request.form.get("mode") == "plan":
            try:
                when = datetime.datetime.strptime(request.form.get("when", ""), "%Y-%m-%dT%H:%M")
            except ValueError:
                flash("Bitte Datum und Uhrzeit für den geplanten Lauf angeben.", "err")
                return redirect(request.referrer or "/")
            if when <= datetime.datetime.now():
                flash("Der geplante Zeitpunkt liegt in der Vergangenheit.", "err")
                return redirect(request.referrer or "/")
            with LOCK:
                plans = load("schedule.json", [])
                plans.append({"id": uuid.uuid4().hex[:8], "when": when.strftime("%Y-%m-%d %H:%M"),
                              "names": [h["name"] for h in sel], "created": now(), "status": "geplant"})
                save("schedule.json", plans)
            flash(f"Update von {len(sel)} Maschine(n) geplant für {when.strftime('%d.%m.%Y %H:%M')}.", "ok")
            return redirect(request.referrer or "/")
        started = launch_mass("update", sel, "Auswahl")
    else:
        sel = [h for h in visible_hosts() if h.get("enabled", True) and h.get("address") and (not grp or h["group"] == grp)
               and (not loc or h.get("location") == loc) and (not stat or status_key(h, st.get(h["name"], {})) == stat)
               and (not updf or updf in upd_keys(h, st.get(h["name"], {})))]
        if kind == "update":
            sel = [h for h in sel if (st.get(h["name"], {}).get("upd") or {}).get("ok") and st[h["name"]]["upd"].get("count")
                   and not h.get("no_mass")]
        started = launch_mass(kind, sel, label)
    if not started:
        flash("Keine passende Maschine" + (" mit offenen Updates." if kind == "update" else "."), "err")
    else:
        flash(("Probelauf" if kind == "check" else "Installation") + " gestartet – " + ", ".join(started)
              + " Maschine(n). Fortschritt unter „Läufe“.", "ok")
    return redirect(request.referrer or "/")


@app.post("/geplant/loeschen")
@run_required
def plan_delete():
    pid = request.form.get("id", "")
    if not can_do("plan"):
        abort(403)
    vis = {h["name"] for h in visible_hosts()}
    with LOCK:
        save("schedule.json", [x for x in load("schedule.json", []) if x["id"] != pid
                               or not (is_admin() or set(x["names"]) <= vis)])
    flash("Geplanter Update-Lauf gelöscht.", "ok")
    return redirect(request.referrer or "/")


def schedule_loop():
    """Geplante Update-Laeufe starten (schedule.json). Mehr als 6 h verpasst (Container war aus) -> "verpasst"."""
    while True:
        time.sleep(30)
        try:
            due = []
            with LOCK:
                plans = load("schedule.json", [])
                nowdt = datetime.datetime.now()
                for x in plans:
                    if x.get("status") != "geplant":
                        continue
                    w = datetime.datetime.strptime(x["when"], "%Y-%m-%d %H:%M")
                    if w > nowdt:
                        continue
                    x["status"] = "verpasst" if nowdt - w > datetime.timedelta(hours=6) else "gestartet"
                    x["started"] = now()
                    if x["status"] == "gestartet":
                        due.append(x)
                save("schedule.json", [x for x in plans if x["status"] == "geplant"
                                       or x.get("started", "") >= (nowdt - datetime.timedelta(days=2)).strftime("%Y-%m-%d")])
            for x in due:
                act = {h["name"] for h in hosts() if h.get("enabled", True) and h.get("address")}
                if x.get("kind") == "reboot":
                    stages = [[n for n in st if n in act] for st in (x.get("stages") or [[n] for n in x["names"]])]
                    stages = [st for st in stages if st]
                    if stages:
                        start_reboot(stages, int(x.get("wait") or 0))
                    continue
                sel = [h for h in hosts() if h["name"] in act and h["name"] in set(x["names"])]
                launch_mass("update", sel, "geplant " + x["when"][8:10] + "." + x["when"][5:7] + ". " + x["when"][11:])
        except Exception:  # noqa: BLE001
            pass


@app.route("/maschine/neu", methods=["GET", "POST"])
@app.route("/maschine/<name>", methods=["GET", "POST"])
@login_required
def machine(name=None):
    if (request.method == "POST" or not name) and not is_admin():
        abort(403)
    if name and not can_see(host(name)):
        abort(404)
    h = host(name) if name else {"name": "", "address": "", "group": "linux", "user": "root", "port": 22,
                                 "enabled": True, "notes": "", "location": request.args.get("standort") or loc_names()[0]}
    if request.method == "POST":
        if request.form.get("delete") and name:
            with LOCK:
                save("hosts.json", [x for x in load("hosts.json", []) if x["name"] != name])
                st = load("status.json", {})
                st.pop(name, None)
                save("status.json", st)
            rename_in_perms("host", name, None)
            try:
                os.unlink(p("facts", name + ".json"))
            except FileNotFoundError:
                pass
            flash(f"{display_name(h)} gelöscht.", "ok")
            return redirect("/")
        display = re.sub(r"\s+", " ", request.form.get("display", "")).strip()[:80]
        tech = request.form.get("name", "").strip() or (name if name else slugify(display))
        new = {
            "name": tech,
            "display": display if display and display != tech else "",
            "address": ", ".join(re.split(r"[,;\s]+", request.form.get("address", "").strip())).strip(", "),
            "group": request.form.get("group", "linux"),
            "user": request.form.get("user", "").strip(),
            "port": int(request.form.get("port") or (5985 if request.form.get("group") == "windows" else 22)),
            "enabled": bool(request.form.get("enabled")),
            "no_mass": bool(request.form.get("no_mass")),
            "notes": request.form.get("notes", "").strip()[:300],
            "profile": request.form.get("profile", ""),
            "location": request.form.get("location") if request.form.get("location") in loc_names() else loc_names()[0],
        }
        err = None
        if not display and not request.form.get("name", "").strip():
            err = "Bitte einen Anzeigenamen angeben."
        elif not NAME_RE.match(new["name"]):
            err = "Technischer Name: nur Buchstaben, Ziffern, Punkt, Minus, Unterstrich (kein Leerzeichen)."
        elif new["address"] and not all(ADDR_RE.match(a) for a in addr_list(new)):
            err = "Adresse ungueltig (mehrere Adressen mit Komma trennen)."
        elif len(addr_list(new)) > 5:
            err = "Höchstens 5 Adressen."
        elif new["group"] not in GROUPS:
            err = "Gruppe ungueltig."
        elif new["user"] and not USER_RE.match(new["user"]):
            err = "Benutzer ungueltig."
        elif new["profile"] and not any(x["id"] == new["profile"] and x["type"] == new["group"]
                                        for x in profiles_data()["profiles"]):
            err = "Das Zugangsprofil passt nicht zur Gruppe."
        with LOCK:
            all_h = load("hosts.json", [])
            if not err and new["name"] != name and any(x["name"] == new["name"] for x in all_h):
                err = "Diesen Namen gibt es schon."
            if err:
                flash(err, "err")
                return render_template("machine.html", h=new, name=name, f={}, s={}, st={}, playbooks=playbooks(),
                                       profiles=profiles_data())
            all_h = [x for x in all_h if x["name"] != name] + [new]
            save("hosts.json", all_h)
            if name and name != new["name"]:
                rename_in_perms("host", name, new["name"])
                st = load("status.json", {})
                if name in st:
                    st[new["name"]] = st.pop(name)
                    save("status.json", st)
                if os.path.exists(p("facts", name + ".json")):
                    os.replace(p("facts", name + ".json"), p("facts", new["name"] + ".json"))
        flash(f"{display_name(new)} gespeichert.", "ok")
        return redirect(url_for("machine", name=new["name"]))
    f = facts_of(name) if name else {}
    st = load("status.json", {}).get(name, {}) if name else {}
    runs = [r for r in load("runs/index.json", []) if name and (name in run_hosts(r) if r.get("hosts") else r["target"] in (name, h["group"], "all"))
            and can_see_run(r)][:15]
    pbs = playbooks_for(h) if name else []
    if not is_admin():  # Benutzer: nur die Update-Playbooks
        pbs = [x for x in pbs if x.startswith("updates-installieren-")]
    return render_template("machine.html", h=h, name=name, f=f, s=summary(f), st=st, playbooks=pbs,
                           pb_default=f"updates-installieren-{h['group']}.yml", runs=runs, profiles=profiles_data(), plabel=profile_label(profile_for(h)) if name else "", facts_json=json.dumps(f, indent=1, ensure_ascii=False, default=str)[:400000])


def playbooks():
    try:
        return sorted(x for x in os.listdir(p("playbooks")) if PB_RE.match(x))
    except FileNotFoundError:
        return []


def playbook_targets(fn):
    """Ziele aus den hosts:-Zeilen eines Playbooks ("linux", "windows", "all", Maschinennamen)."""
    try:
        with open(p("playbooks", fn)) as f:
            plays = yaml.safe_load(f) or []
    except (OSError, yaml.YAMLError):
        return set()
    out = set()
    for play in plays if isinstance(plays, list) else []:
        if isinstance(play, dict) and play.get("hosts"):
            hs = play["hosts"] if isinstance(play["hosts"], list) else re.split(r"[,:]", str(play["hosts"]))
            out.update(x.strip() for x in hs if x.strip())
    return out


def playbooks_for(h):
    """Nur Playbooks, die fuer diese Maschine gelten (ihre Gruppe, "all"/"*" oder ihr Name)."""
    return [fn for fn in playbooks() if playbook_targets(fn) & {h["group"], h["name"], "all", "*"}]


@app.route("/playbooks", methods=["GET", "POST"])
@admin_required
def playbook_list():
    if request.method == "POST":
        fn = request.form.get("filename", "").strip()
        if not PB_RE.match(fn):
            flash("Dateiname muss auf .yml oder .yaml enden (nur Buchstaben, Ziffern, . _ -).", "err")
        elif request.form.get("delete"):
            try:
                os.unlink(p("playbooks", fn))
                flash(f"{fn} geloescht.", "ok")
            except FileNotFoundError:
                pass
            return redirect(url_for("playbook_list"))
        else:
            content = request.form.get("content", "").replace("\r\n", "\n")
            try:
                yaml.safe_load(content)
            except yaml.YAMLError as ex:
                flash(f"YAML-Fehler: {ex}", "err")
                return render_template("playbooks.html", items=playbooks(), edit=fn, content=content)
            with open(p("playbooks", fn), "w") as f:
                f.write(content)
            flash(f"{fn} gespeichert.", "ok")
            return redirect(url_for("playbook_list", datei=fn))
    edit = request.args.get("datei", "")
    content = ""
    if edit and PB_RE.match(edit) and os.path.exists(p("playbooks", edit)):
        with open(p("playbooks", edit)) as f:
            content = f.read()
    return render_template("playbooks.html", items=playbooks(), edit=edit, content=content)


@app.post("/playbook/start")
@run_required
def playbook_start():
    pb = request.form.get("playbook", "")
    target = request.form.get("target", "")
    if pb not in playbooks():
        abort(400)
    if is_admin():
        valid = {"all", *GROUPS, *(h["name"] for h in hosts() if h.get("enabled", True))}
    else:  # Benutzer: nur Update-Playbooks auf einzelne sichtbare Maschinen
        valid = {h["name"] for h in visible_hosts() if h.get("enabled", True)} if pb.startswith("updates-installieren-") else set()
    if target not in valid:
        abort(400 if is_admin() else 403)
    check = bool(request.form.get("check"))
    if not is_admin() and not can_do("upd_check" if check else "upd_install"):
        abort(403)
    rid = new_run("playbook", target, f"{pb} auf {target}" + (" (Probelauf)" if check else ""),
                  [target] if target not in ("all", *GROUPS) else None)
    start(playbook_job, rid, pb, target, check)
    return redirect(url_for("run_view", rid=rid))


@app.route("/laeufe")
@login_required
def runs():
    return render_template("runs.html", runs=[r for r in load("runs/index.json", []) if can_see_run(r)][:200])


@app.route("/laeufe/<rid>")
@login_required
def run_view(rid):
    if not re.match(r"^[0-9a-f-]+$", rid):
        abort(404)
    r = next((x for x in load("runs/index.json", []) if x["id"] == rid), None)
    if not r or not can_see_run(r):
        abort(404)
    try:
        with open(p("runs", rid + ".log")) as f:
            text = f.read()[-300000:]
    except FileNotFoundError:
        text = ""
    back = next((h for h in visible_hosts() if h["name"] == r.get("target")), None)
    return render_template("run.html", r=r, text=text, back=back)


@app.route("/einstellungen", methods=["GET", "POST"])
@admin_required
def settings():
    sec = load("secrets.json", {})
    if request.method == "POST" and request.form.get("form") == "password":
        old, new, rep_ = (request.form.get(k, "") for k in ("old_password", "new_password", "new_password2"))
        if not check_admin(old):
            flash("Aktuelles Passwort ist falsch.", "err")
        elif len(new) < 10:
            flash("Das neue Passwort muss mindestens 10 Zeichen haben.", "err")
        elif new != rep_:
            flash("Die beiden neuen Passwörter stimmen nicht überein.", "err")
        else:
            save("auth.json", {"hash": generate_password_hash(new), "changed": now()}, 0o600)
            flash("Admin-Passwort geändert.", "ok")
        return redirect(url_for("settings"))
    if request.method == "POST" and request.form.get("form") == "updates":
        with LOCK:
            s = settings_data()
            s["upd_nightly"] = bool(request.form.get("upd_nightly"))
            t = request.form.get("upd_time", "")
            if re.match(r"^([01][0-9]|2[0-3]):[0-5][0-9]$", t):
                s["upd_time"] = t
            save("settings.json", s)
        flash("Update-Prüfung gespeichert.", "ok")
        return redirect(url_for("settings") + "#updates")
    if request.method == "POST" and request.form.get("form") == "location":
        location_action(request.form)
        return redirect(url_for("settings") + "#standorte")
    if request.method == "POST" and request.form.get("form") == "defaults":
        with LOCK:
            sec = profiles_data()
            for g in GROUPS:
                v = request.form.get("default_" + g, "")
                if any(x["id"] == v and x["type"] == g for x in sec["profiles"]):
                    sec["defaults"][g] = v
            save("secrets.json", sec, 0o600)
        flash("Standardprofile gespeichert.", "ok")
        return redirect(url_for("settings"))
    try:
        with open(p("ssh", "id_ed25519.pub")) as f:
            pub = f.read().strip()
    except FileNotFoundError:
        pub = "(noch kein Schluessel)"
    try:
        ver = subprocess.run(["ansible", "--version"], capture_output=True, text=True, timeout=30).stdout.splitlines()[:1]
    except (OSError, subprocess.TimeoutExpired):
        ver = []
    sec = profiles_data()
    used = {}
    for h in hosts():
        pr = profile_for(h, sec)
        if pr:
            used.setdefault(pr["id"], []).append(h["name"])
    loc_count = {}
    for h in hosts():
        loc_count[h.get("location")] = loc_count.get(h.get("location"), 0) + 1
    return render_template("settings.html", pub=pub, sec=sec, ver=ver[0] if ver else "", auth=load("auth.json", {}),
                           used=used, label=profile_label, locs=locations(), loc_count=loc_count, conf=settings_data())


def parse_nets(raw):
    nets = [x.strip() for x in re.split(r"[,\s;]+", raw or "") if x.strip()]
    bad = [x for x in nets if not NET_RE.match(x)]
    return nets, bad


def location_action(f):
    """Standort anlegen / umbenennen / Netze aendern / verschieben / loeschen."""
    act = f.get("act", "")
    with LOCK:
        locs = locations()
        names = [x["name"] for x in locs]
        idx = int(f.get("idx", -1)) if f.get("idx", "").lstrip("-").isdigit() else -1
        if act == "add":
            name = f.get("name", "").strip()
            nets, bad = parse_nets(f.get("nets"))
            if not LOCNAME_RE.match(name) or name in names:
                flash("Name fehlt, ist ungültig oder existiert schon.", "err")
            elif bad:
                flash("Ungültige Netze: " + ", ".join(bad) + " (Beispiel: 192.168.2.)", "err")
            else:
                locs.append({"name": name, "nets": nets})
                save("locations.json", locs)
                flash(f"Standort „{name}“ angelegt.", "ok")
            return
        if not 0 <= idx < len(locs):
            abort(400)
        old = locs[idx]["name"]
        if act == "save":
            name = f.get("name", "").strip()
            nets, bad = parse_nets(f.get("nets"))
            if not LOCNAME_RE.match(name) or (name != old and name in names):
                flash("Name ungültig oder schon vergeben.", "err")
                return
            if bad:
                flash("Ungültige Netze: " + ", ".join(bad) + " (Beispiel: 192.168.2.)", "err")
                return
            locs[idx] = {"name": name, "nets": nets}
            save("locations.json", locs)
            if name != old:
                hs = load("hosts.json", [])
                for h in hs:
                    if h.get("location") == old:
                        h["location"] = name
                save("hosts.json", hs)
                rename_in_perms("location", old, name)
            flash(f"Standort „{name}“ gespeichert.", "ok")
        elif act in ("up", "down"):
            j = idx - 1 if act == "up" else idx + 1
            if 0 <= j < len(locs):
                locs[idx], locs[j] = locs[j], locs[idx]
                save("locations.json", locs)
        elif act == "delete":
            if len(locs) == 1:
                flash("Der letzte Standort kann nicht gelöscht werden.", "err")
                return
            hs = load("hosts.json", [])
            affected = [h for h in hs if h.get("location") == old]
            target = f.get("move_to", "")
            if affected and (target not in names or target == old):
                flash(f"„{old}“ hat noch {len(affected)} Maschine(n) – bitte wählen, wohin sie verschoben werden.", "err")
                return
            for h in affected:
                h["location"] = target
            if affected:
                save("hosts.json", hs)
            del locs[idx]
            save("locations.json", locs)
            rename_in_perms("location", old, None)
            flash(f"Standort „{old}“ gelöscht" + (f", {len(affected)} Maschine(n) nach „{target}“ verschoben." if affected else "."), "ok")


@app.route("/profil/neu", methods=["GET", "POST"])
@app.route("/profil/<pid>", methods=["GET", "POST"])
@admin_required
def profile_edit(pid=None):
    sec = profiles_data()
    pr = next((x for x in sec["profiles"] if x["id"] == pid), None) if pid else blank_profile(request.args.get("typ", "linux"))
    if pr is None or pr["type"] not in GROUPS:
        abort(404)
    if request.method == "POST":
        if request.form.get("delete") and pid:
            users = [h["name"] for h in hosts() if h.get("profile") == pid]
            if pid in sec["defaults"].values():
                flash("Das ist ein Standardprofil – erst ein anderes als Standard wählen.", "err")
            elif users:
                flash("Wird noch verwendet von: " + ", ".join(users), "err")
            else:
                with LOCK:
                    sec["profiles"] = [x for x in sec["profiles"] if x["id"] != pid]
                    save("secrets.json", sec, 0o600)
                flash("Profil gelöscht.", "ok")
                return redirect(url_for("settings"))
            return redirect(url_for("profile_edit", pid=pid))
        f = request.form
        new = dict(pr)
        new.update(name=f.get("name", "").strip()[:80], user=f.get("user", "").strip())
        if pr["type"] == "linux":
            new.update(auth=f.get("auth") if f.get("auth") in ("key", "password") else "key",
                       become=f.get("become") if f.get("become") in ("none", "sudo", "su") else "none",
                       become_user=f.get("become_user", "").strip() or "root")
        else:
            new.update(transport=f.get("transport") if f.get("transport") in ("ntlm", "kerberos", "credssp", "basic") else "ntlm")
        for k in ("password", "become_password"):
            if f.get(k):
                new[k] = f[k]
            if f.get("clear_" + k):
                new[k] = ""
        if new["auth"] != "password" and pr["type"] == "linux":
            new["password"] = ""
        if new["become"] == "none":
            new["become_password"] = ""
        err = None
        if not new["name"]:
            err = "Bitte einen Namen angeben."
        elif new["user"] and not USER_RE.match(new["user"]):
            err = "Benutzer ungültig."
        elif not USER_RE.match(new["become_user"] or "root"):
            err = "Zielbenutzer ungültig."
        if err:
            flash(err, "err")
            return render_template("profile.html", pr=new, pid=pid)
        with LOCK:
            sec = profiles_data()
            if not pid:
                base = re.sub(r"[^a-z0-9]+", "-", new["name"].lower()).strip("-")[:30] or "profil"
                new["id"] = base
                i = 2
                while any(x["id"] == new["id"] for x in sec["profiles"]):
                    new["id"] = f"{base}-{i}"
                    i += 1
                sec["profiles"].append(new)
            else:
                sec["profiles"] = [new if x["id"] == pid else x for x in sec["profiles"]]
            save("secrets.json", sec, 0o600)
        flash(f'Profil „{new["name"]}“ gespeichert.', "ok")
        return redirect(url_for("settings"))
    return render_template("profile.html", pr=pr, pid=pid)



USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,40}$")


def pw_problem(new, rep_):
    if len(new) < 10:
        return "Das Passwort muss mindestens 10 Zeichen haben."
    if new != rep_:
        return "Die beiden Passwörter stimmen nicht überein."
    return None


def perms_summary(u):
    out = []
    for loc, v in (u.get("perms") or {}).items():
        what = {"*": "alle", "group:linux": "alle Linux", "group:windows": "alle Windows"}.get(v) if isinstance(v, str) else f"{len(v)} Maschine(n)"
        out.append(f"{loc or 'ohne Standort'}: {what}")
    return out


@app.route("/benutzer")
@admin_required
def user_list():
    gname = {g["id"]: g["name"] for g in groups_data()}
    return render_template("users.html", users=users_data(), summary=perms_summary, now_ts=time.time(), actions=ACTIONS,
                           eff_actions=eff_actions, gname=gname)


@app.route("/benutzer/neu", methods=["GET", "POST"])
@app.route("/benutzer/<uname>", methods=["GET", "POST"])
@admin_required
def user_edit(uname=None):
    u = find_user(uname) if uname else {"name": "", "source": "local", "email": "", "actions": [], "groups": [], "perms": {}}
    if u is None:
        abort(404)
    hs = hosts()
    locs = loc_names() + ([""] if any(not h.get("location") for h in hs) else [])

    def store(name, **kw):
        with LOCK:
            us = users_data()
            for x in us:
                if x["name"] == name:
                    x.update(kw)
                    for k, v in kw.items():
                        if v is None:
                            x.pop(k, None)
            save("users.json", us, 0o600)

    if request.method == "POST":
        act = request.form.get("act", "save")
        if act == "delete" and uname:
            with LOCK:
                save("users.json", [x for x in users_data() if x["name"] != uname], 0o600)
            flash(f"Benutzer {uname} gelöscht.", "ok")
            return redirect(url_for("user_list"))
        if act == "resetpw" and uname and u.get("source") != "ad":  # Zufallspasswort, einmal anzeigen, beim Login aendern
            pw = gen_password()
            store(uname, hash=generate_password_hash(pw), must_change=True, invite=None, changed=now())
            flash(f"Neues Passwort für {uname}: {pw}   – nur jetzt sichtbar; muss beim nächsten Login geändert werden.", "ok")
            return redirect(url_for("user_edit", uname=uname))
        if act in ("invite", "resetmail") and uname:
            if not u.get("email"):
                flash("Für diesen Benutzer ist keine E-Mail-Adresse eingetragen.", "err")
                return redirect(url_for("user_edit", uname=uname))
            try:
                tok = None
                if u.get("source") != "ad":
                    tmp = dict(u)
                    tok = make_invite(tmp)
                    store(uname, invite=tmp["invite"])
                invite_mail(u, tok)
                flash(f"E-Mail an {u['email']} gesendet.", "ok")
            except Exception as ex:  # noqa: BLE001
                flash(f"E-Mail konnte nicht gesendet werden: {ex}", "err")
            return redirect(url_for("user_edit", uname=uname))
        name = uname or request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        perms = parse_perms(request.form, locs, hs)
        actions = [k for k in ACTIONS if request.form.get("a_" + k)]
        gids = {g["id"] for g in groups_data()}
        ugroups = [x for x in request.form.getlist("grp") if x in gids]
        is_ad = u.get("source") == "ad"
        new_pw, rep_ = request.form.get("password", ""), request.form.get("password2", "")
        send_inv = bool(request.form.get("send_invite")) and not uname
        err = None
        if not uname and (not USERNAME_RE.match(name) or name == ADMIN_USER or find_user(name) or find_login(name)):
            err = "Benutzername ungültig oder schon vergeben (2–41 Zeichen: Buchstaben, Ziffern, . _ @ -)."
        elif email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            err = "E-Mail-Adresse ungültig."
        elif send_inv and not email:
            err = "Für die Einladung wird eine E-Mail-Adresse gebraucht."
        elif not is_ad and not send_inv and (new_pw or not uname) and pw_problem(new_pw, rep_):
            err = pw_problem(new_pw, rep_)
        if err:
            flash(err, "err")
            return render_template("user.html", u={**u, "name": name, "email": email, "actions": actions, "groups": ugroups,
                                                    "perms": perms}, uname=uname, locs=locs, hs=hs, **user_ctx())
        with LOCK:
            us = users_data()
            cur = next((x for x in us if x["name"] == name), None)
            if cur is None:
                cur = {"name": name, "source": "local", "created": now()}
                us.append(cur)
            cur.update(actions=actions, groups=ugroups, perms=perms, email=email, changed=now())
            cur.pop("can_run", None)
            if new_pw and not is_ad:
                cur["hash"] = generate_password_hash(new_pw)
                cur.pop("must_change", None)
                if request.form.get("must_change"):
                    cur["must_change"] = True
            tok = make_invite(cur) if send_inv else None
            save("users.json", us, 0o600)
        msg = f"Benutzer {name} gespeichert."
        if send_inv:
            try:
                invite_mail(cur, tok)
                msg += f" Einladung an {email} gesendet."
            except Exception as ex:  # noqa: BLE001
                flash(f"Benutzer angelegt, aber die Einladung konnte nicht gesendet werden: {ex}", "err")
        if not perms and not ugroups:
            flash(msg + " Achtung: weder Standorte noch Gruppe – sieht nichts.", "err")
        else:
            flash(msg, "ok")
        return redirect(url_for("user_edit", uname=name))
    return render_template("user.html", u=u, uname=uname, locs=locs, hs=hs, **user_ctx())


def user_ctx():
    return {"mail_ok": bool(dir_conf()["mail"]["host"]), "now_ts": time.time(), "actions": ACTIONS, "all_groups": groups_data(),
            "own_actions": own_actions, "eff_actions": eff_actions}


def parse_perms(form, locs, hs):
    perms = {}
    for i, loc in enumerate(locs):
        mode = form.get(f"m{i}", "")
        if mode == "all":
            perms[loc] = "*"
        elif mode in ("linux", "windows"):
            perms[loc] = "group:" + mode
        elif mode == "sel":
            names = [x for x in form.getlist(f"h{i}") if any(h["name"] == x and (h.get("location") or "") == loc for h in hs)]
            if names:
                perms[loc] = names
    return perms


@app.route("/benutzer/gruppen")
@admin_required
def group_list():
    us = users_data()
    members = {g["id"]: [u["name"] for u in us if g["id"] in (u.get("groups") or [])] for g in groups_data()}
    return render_template("groups.html", grps=groups_data(), members=members, summary=perms_summary, actions=ACTIONS)


@app.route("/benutzer/gruppe/neu", methods=["GET", "POST"])
@app.route("/benutzer/gruppe/<gid>", methods=["GET", "POST"])
@admin_required
def group_edit(gid=None):
    g = next((x for x in groups_data() if x["id"] == gid), None) if gid else {"id": "", "name": "", "actions": [], "perms": {}}
    if g is None:
        abort(404)
    hs = hosts()
    locs = loc_names() + ([""] if any(not h.get("location") for h in hs) else [])
    us = users_data()
    if request.method == "POST":
        if request.form.get("act") == "delete" and gid:
            with LOCK:
                save("groups.json", [x for x in groups_data() if x["id"] != gid], 0o600)
                us = users_data()
                for u in us:
                    if gid in (u.get("groups") or []):
                        u["groups"] = [x for x in u["groups"] if x != gid]
                save("users.json", us, 0o600)
            flash(f"Gruppe {g['name']} gelöscht.", "ok")
            return redirect(url_for("group_list"))
        name = re.sub(r"\s+", " ", request.form.get("name", "")).strip()[:60]
        new = {"name": name, "actions": [k for k in ACTIONS if request.form.get("a_" + k)], "perms": parse_perms(request.form, locs, hs)}
        if not name or not LOCNAME_RE.match(name) or any(x["name"].lower() == name.lower() and x["id"] != gid for x in groups_data()):
            flash("Name fehlt, ist ungültig oder schon vergeben.", "err")
            return render_template("group.html", g={**g, **new}, gid=gid, locs=locs, hs=hs, actions=ACTIONS, us=us,
                                   members=set(request.form.getlist("member")))
        with LOCK:
            gs = groups_data()
            cur = next((x for x in gs if x["id"] == gid), None)
            if cur is None:
                cur = {"id": uuid.uuid4().hex[:8], "created": now()}
                gs.append(cur)
            cur.update(new, changed=now())
            save("groups.json", gs, 0o600)
            mem = set(request.form.getlist("member"))
            us = users_data()
            for u in us:
                have = cur["id"] in (u.get("groups") or [])
                if (u["name"] in mem) != have:
                    u["groups"] = [x for x in (u.get("groups") or []) if x != cur["id"]] + ([cur["id"]] if u["name"] in mem else [])
            save("users.json", us, 0o600)
        flash(f"Gruppe {name} gespeichert.", "ok")
        return redirect(url_for("group_edit", gid=cur["id"]))
    return render_template("group.html", g=g, gid=gid, locs=locs, hs=hs, actions=ACTIONS, us=us,
                           members={u["name"] for u in us if gid and gid in (u.get("groups") or [])})


# ---------------------------------------------------------------- E-Mail und Active Directory
# directory.json (0600): {"mail": {...}, "ad": {...}}; Passwoerter darin im Klartext (wie secrets.json), nur im Daten-Volume.
MAIL_DEFAULT = {"host": "", "port": 587, "security": "starttls", "user": "", "password": "", "sender": "", "base_url": ""}
AD_DEFAULT = {"enabled": False, "servers": "", "port": 389, "security": "starttls", "verify": False, "base_dn": "",
              "bind_user": "", "bind_password": "", "domain": "", "user_filter": ""}
INVITE_HOURS = 72


def dir_conf():
    d = load("directory.json", {})
    return {"mail": {**MAIL_DEFAULT, **(d.get("mail") or {})}, "ad": {**AD_DEFAULT, **(d.get("ad") or {})}}


def base_url():
    b = dir_conf()["mail"]["base_url"].strip().rstrip("/")
    return b or (request.url_root.rstrip("/") if has_request_context() else "")


def send_mail(to, subject, body):
    m = dir_conf()["mail"]
    if not m["host"] or not m["sender"]:
        raise RuntimeError("E-Mail ist nicht eingerichtet (Benutzer › E-Mail & AD).")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = m["sender"], to, subject
    msg.set_content(body)
    ctx = ssl.create_default_context()
    port = int(m["port"] or 0)
    if m["security"] == "ssl":
        srv = smtplib.SMTP_SSL(m["host"], port or 465, timeout=20, context=ctx)
    else:
        srv = smtplib.SMTP(m["host"], port or 587, timeout=20)
        if m["security"] == "starttls":
            srv.starttls(context=ctx)
    with srv:
        if m["user"]:
            srv.login(m["user"], m["password"])
        srv.send_message(msg)


def gen_password(n=16):
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    while True:
        pw = "".join(secrets.choice(alpha + "!#%+-=?") for _ in range(n))
        if re.search(r"[A-Z]", pw) and re.search(r"[a-z]", pw) and re.search(r"[0-9]", pw) and re.search(r"[!#%+\-=?]", pw):
            return pw


def make_invite(u):
    t = secrets.token_urlsafe(32)
    u["invite"] = {"hash": hashlib.sha256(t.encode()).hexdigest(), "expires": int(time.time()) + INVITE_HOURS * 3600}
    return t


def invite_mail(u, token=None):
    """Einladung bzw. Passwort-Link (lokal) oder Zugangsinfo (AD) per E-Mail."""
    url = base_url()
    if u.get("source") == "ad":
        body = (f"Hallo {u.get('display') or u['name']},\n\ndu hast jetzt Zugriff auf die Ansible-UI:\n{url}/\n\n"
                f"Anmeldung mit deinem Domänen-Benutzer „{u['name']}“ und deinem gewohnten Windows-Passwort.\n")
        subject = "Zugang zur Ansible-UI"
    else:
        body = (f"Hallo {u['name']},\n\nfür dich wurde ein Zugang zur Ansible-UI eingerichtet bzw. zurückgesetzt.\n"
                f"Über diesen Link legst du dein Passwort fest (gültig {INVITE_HOURS} Stunden):\n\n{url}/einladung/{token}\n\n"
                f"Benutzername: {u['name']}\n\nWenn du das nicht erwartet hast, kannst du diese E-Mail ignorieren.\n")
        subject = "Einladung zur Ansible-UI"
    send_mail(u["email"], subject, body)


def find_login(name):
    """Anmeldename -> Benutzer; AD-Benutzer ohne Gross-/Kleinschreibung und auch als DOMAENE\\name oder name@domain."""
    u = find_user(name)
    if u:
        return u
    short = name.split("\\")[-1].split("@")[0].lower()
    return next((x for x in users_data() if x.get("source") == "ad" and x["name"].lower() == short), None)


def _ldap():
    import ldap3  # noqa: PLC0415 - nur noetig, wenn AD benutzt wird
    return ldap3


def ad_connection(conf, user=None, password=None):
    """Verbindung zum ersten erreichbaren DC; Rueckgabe (conn, fehler)."""
    ldap3 = _ldap()
    hosts_ = [h.strip() for h in re.split(r"[,\s;]+", conf["servers"]) if h.strip()]
    if not hosts_:
        return None, "Kein Domänencontroller eingetragen."
    tls = ldap3.Tls(validate=ssl.CERT_REQUIRED if conf["verify"] else ssl.CERT_NONE)
    last = ""
    for h in hosts_:
        try:
            srv = ldap3.Server(h, port=int(conf["port"] or (636 if conf["security"] == "ldaps" else 389)),
                               use_ssl=conf["security"] == "ldaps", tls=tls, get_info=ldap3.NONE, connect_timeout=5)
            c = ldap3.Connection(srv, user=user, password=password, receive_timeout=10, raise_exceptions=False,
                                 authentication=ldap3.SIMPLE if user else ldap3.ANONYMOUS)
            c.open()  # gibt nichts zurueck - Zustand ueber c.closed pruefen
            if c.closed:
                last = f"{h}: nicht erreichbar ({c.last_error or 'keine Verbindung'})"
                continue
            if conf["security"] == "starttls" and not c.start_tls():
                last = f"{h}: StartTLS fehlgeschlagen ({c.result.get('description')})"
                continue
            if not c.bind():
                return None, f"{h}: Anmeldung abgelehnt ({c.result.get('description')})"
            return c, ""
        except Exception as ex:  # noqa: BLE001
            last = f"{h}: {ex}"
    return None, last or "keine Verbindung"


def ad_service():
    conf = dir_conf()["ad"]
    if not conf["enabled"]:
        return None, "AD ist nicht aktiviert."
    if not conf["bind_user"] or not conf["bind_password"]:
        return None, "Dienstkonto (Benutzer/Passwort) fehlt."
    return ad_connection(conf, conf["bind_user"], conf["bind_password"])


AD_ATTRS = ["sAMAccountName", "displayName", "mail", "userPrincipalName", "distinguishedName", "userAccountControl"]


def ad_entry(e):
    a = e.entry_attributes_as_dict
    one = lambda k: (a.get(k) or [""])[0]  # noqa: E731
    return {"sam": str(one("sAMAccountName")), "display": str(one("displayName")), "mail": str(one("mail")),
            "upn": str(one("userPrincipalName")), "dn": str(e.entry_dn),
            "disabled": bool(int(one("userAccountControl") or 0) & 2)}


def ad_filter(inner):
    extra = dir_conf()["ad"]["user_filter"].strip()
    if extra and not extra.startswith("("):
        extra = f"({extra})"
    return f"(&(objectCategory=person)(objectClass=user){inner}{extra})"


def ad_search(q, limit=50):
    c, err = ad_service()
    if not c:
        return [], err
    esc = _ldap().utils.conv.escape_filter_chars(q.strip())
    inner = f"(|(sAMAccountName=*{esc}*)(displayName=*{esc}*)(mail=*{esc}*))" if esc else "(sAMAccountName=*)"
    try:
        c.search(dir_conf()["ad"]["base_dn"], ad_filter(inner), attributes=AD_ATTRS, size_limit=limit)
        return sorted((ad_entry(e) for e in c.entries), key=lambda x: (x["display"] or x["sam"]).lower()), ""
    finally:
        c.unbind()


def ad_lookup(sam):
    c, err = ad_service()
    if not c:
        return None, err
    esc = _ldap().utils.conv.escape_filter_chars(sam)
    try:
        c.search(dir_conf()["ad"]["base_dn"], ad_filter(f"(sAMAccountName={esc})"), attributes=AD_ATTRS, size_limit=2)
        return (ad_entry(c.entries[0]) if len(c.entries) == 1 else None), ("" if c.entries else "nicht gefunden (oder durch Filter ausgeschlossen)")
    finally:
        c.unbind()


def ad_authenticate(u, pw):
    """AD-Anmeldung: Konto per Dienstkonto suchen (aktuell, aktiv, Filter), dann mit seinem DN und Passwort binden."""
    if not pw:  # leeres Passwort = anonymer Bind, wuerde "klappen"
        return False, "leeres Passwort"
    try:
        e, err = ad_lookup(u["name"])
        if not e:
            return False, err
        if e["disabled"]:
            return False, "Konto im AD deaktiviert"
        c, err = ad_connection(dir_conf()["ad"], e["dn"], pw)
        if not c:
            return False, err
        c.unbind()
        with LOCK:  # Anzeigename/E-Mail aktuell halten
            us = users_data()
            for x in us:
                if x["name"] == u["name"]:
                    x.update(ad_dn=e["dn"], display=e["display"] or x.get("display", ""), email=x.get("email") or e["mail"])
            save("users.json", us, 0o600)
        return True, ""
    except Exception as ex:  # noqa: BLE001
        return False, str(ex)


@app.route("/benutzer/verzeichnis", methods=["GET", "POST"])
@admin_required
def directory_settings():
    if request.method == "POST":
        form = request.form.get("form")
        d = load("directory.json", {})
        if form == "mail":
            m = {**MAIL_DEFAULT, **(d.get("mail") or {})}
            for k in ("host", "user", "sender", "base_url"):
                m[k] = request.form.get(k, "").strip()
            m["port"] = int(request.form.get("port") or 0) or (465 if request.form.get("security") == "ssl" else 587)
            m["security"] = request.form.get("security") if request.form.get("security") in ("starttls", "ssl", "none") else "starttls"
            if request.form.get("password"):
                m["password"] = request.form.get("password")
            if request.form.get("clear_password"):
                m["password"] = ""
            d["mail"] = m
            save("directory.json", d, 0o600)
            flash("E-Mail-Einstellungen gespeichert.", "ok")
            if request.form.get("test_to"):
                try:
                    send_mail(request.form["test_to"].strip(), "Ansible-UI: Test-E-Mail", "Die E-Mail-Einstellungen der Ansible-UI funktionieren.\n")
                    flash(f"Test-E-Mail an {request.form['test_to'].strip()} gesendet.", "ok")
                except Exception as ex:  # noqa: BLE001
                    flash(f"Test-E-Mail fehlgeschlagen: {ex}", "err")
            return redirect(url_for("directory_settings") + "#mail")
        if form == "ad":
            a = {**AD_DEFAULT, **(d.get("ad") or {})}
            for k in ("servers", "base_dn", "bind_user", "domain", "user_filter"):
                a[k] = request.form.get(k, "").strip()
            a["security"] = request.form.get("security") if request.form.get("security") in ("starttls", "ldaps", "none") else "starttls"
            a["port"] = int(request.form.get("port") or 0) or (636 if a["security"] == "ldaps" else 389)
            a["verify"] = bool(request.form.get("verify"))
            a["enabled"] = bool(request.form.get("enabled"))
            if request.form.get("bind_password"):
                a["bind_password"] = request.form.get("bind_password")
            d["ad"] = a
            save("directory.json", d, 0o600)
            flash("AD-Einstellungen gespeichert.", "ok")
            if request.form.get("test"):
                try:
                    found, err = ad_search("", limit=500)
                    if err:
                        flash(f"AD-Test fehlgeschlagen: {err}", "err")
                    else:
                        flash(f"AD-Verbindung ok – {len(found)} Benutzer gefunden (max. 500 gezählt).", "ok")
                except Exception as ex:  # noqa: BLE001
                    flash(f"AD-Test fehlgeschlagen: {ex}", "err")
            return redirect(url_for("directory_settings") + "#ad")
    c = dir_conf()
    return render_template("directory.html", mail=c["mail"], ad=c["ad"])


@app.route("/benutzer/ad", methods=["GET", "POST"])
@admin_required
def ad_add():
    if request.method == "POST":
        sam = request.form.get("sam", "")
        e, err = ad_lookup(sam)
        if not e:
            flash(f"AD-Benutzer nicht übernommen: {err}", "err")
            return redirect(url_for("ad_add", q=sam))
        if e["sam"] == ADMIN_USER or find_user(e["sam"]) or find_login(e["sam"]):
            flash(f"Einen Benutzer „{e['sam']}“ gibt es schon.", "err")
            return redirect(url_for("ad_add", q=sam))
        with LOCK:
            us = users_data()
            us.append({"name": e["sam"], "source": "ad", "display": e["display"], "email": e["mail"], "ad_dn": e["dn"],
                       "actions": [], "groups": [], "perms": {}, "created": now(), "changed": now()})
            save("users.json", us, 0o600)
        flash(f"AD-Benutzer {e['display'] or e['sam']} übernommen – jetzt die Rechte festlegen.", "ok")
        return redirect(url_for("user_edit", uname=e["sam"]))
    q = request.args.get("q", "")
    res, err = ([], "")
    if "q" in request.args:
        try:
            res, err = ad_search(q)
        except Exception as ex:  # noqa: BLE001
            err = str(ex)
    have = {u["name"].lower() for u in users_data()}
    return render_template("ad_add.html", q=q, res=res, err=err, have=have, conf=dir_conf()["ad"])


@app.route("/einladung/<token>", methods=["GET", "POST"])
def invite(token):
    th = hashlib.sha256(token.encode()).hexdigest()
    u = next((x for x in users_data() if (x.get("invite") or {}).get("hash") == th), None)
    if not u or u["invite"]["expires"] < time.time():
        return render_template("invite.html", u=None)
    if request.method == "POST":
        new, rep_ = request.form.get("new_password", ""), request.form.get("new_password2", "")
        if pw_problem(new, rep_):
            flash(pw_problem(new, rep_), "err")
        else:
            with LOCK:
                us = users_data()
                for x in us:
                    if x["name"] == u["name"]:
                        x["hash"], x["changed"] = generate_password_hash(new), now()
                        x.pop("invite", None)
                        x.pop("must_change", None)
                save("users.json", us, 0o600)
            flash("Passwort gespeichert – jetzt anmelden.", "ok")
            return redirect(url_for("login"))
    return render_template("invite.html", u=u)

@app.route("/passwort", methods=["GET", "POST"])
@login_required
def own_password():
    if is_admin():
        return redirect(url_for("settings") + "#passwort")
    if (cur_user() or {}).get("source") == "ad":
        flash("Du meldest dich mit deinem Domänen-Konto an – das Passwort änderst du in Windows bzw. im AD.", "ok")
        return redirect("/")
    if request.method == "POST":
        u = cur_user()
        old, new, rep_ = (request.form.get(k, "") for k in ("old_password", "new_password", "new_password2"))
        if not check_password_hash(u["hash"], old):
            flash("Aktuelles Passwort ist falsch.", "err")
        elif pw_problem(new, rep_):
            flash(pw_problem(new, rep_), "err")
        else:
            with LOCK:
                us = users_data()
                for x in us:
                    if x["name"] == u["name"]:
                        x["hash"], x["changed"] = generate_password_hash(new), now()
                        x.pop("must_change", None)
                save("users.json", us, 0o600)
            flash("Passwort geändert.", "ok")
            return redirect("/")
    return render_template("password.html")


@app.errorhandler(403)
def forbidden(_e):
    return render_template("forbidden.html"), 403

@app.get("/health")
def health():
    return {"ok": True}


# ---------------------------------------------------------------- Vorlagen
BASE = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}Ansible{% endblock %} - Ansible-UI</title>
{% block head %}{% endblock %}
<style>
:root{--bg:#14181f;--panel:#1d2430;--line:#2c3545;--text:#e6e9ef;--mut:#93a0b4;--acc:#f28c28;--ok:#3fb950;--err:#f85149;--warn:#d29922}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}
a{color:#7cb7ff;text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;gap:18px;align-items:center;padding:10px 20px;background:#0f1a2b;border-bottom:2px solid var(--acc)}
header b{font-size:17px;color:var(--acc)}header nav a{color:var(--text);margin-right:14px}header .sp{flex:1}
main{padding:18px 20px;max-width:1900px;margin:auto}
.fit{width:fit-content;max-width:100%;margin:0 auto}table.auto{width:auto}
h1{font-size:20px;margin:4px 0 14px}h2{font-size:16px;margin:22px 0 8px;color:var(--mut)}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:#243044;color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
tr.off td{opacity:.5}
tr.locstart td{border-top:3px solid #3a4a63}
select.thsel{width:auto;background:transparent;border:1px solid transparent;color:var(--mut);font-size:12px;font-weight:600;text-transform:uppercase;padding:2px 4px;cursor:pointer}
select.thsel:hover{border-color:#3c4b66}select.thsel.on{color:var(--acc);border-color:var(--acc)}
select.thsel option{text-transform:none;color:var(--text);background:var(--panel)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:#56606f;margin-right:6px}
.dot.ok{background:var(--ok)}.dot.err{background:var(--err)}
.mut{color:var(--mut)}.small{font-size:12px}
.btn,button{background:#2d3a50;color:var(--text);border:1px solid #3c4b66;border-radius:6px;padding:5px 11px;cursor:pointer;font:inherit}
.btn:hover,button:hover{border-color:var(--acc);text-decoration:none}
.btn.acc,button.acc{background:var(--acc);border-color:var(--acc);color:#111;font-weight:600}
button.danger{background:#5a1d1d;border-color:#8a2c2c}
form.inl{display:inline}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.flash{padding:9px 12px;border-radius:6px;margin-bottom:12px}.flash.ok{background:#173b22}.flash.err{background:#4a1c1c}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin-bottom:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;align-items:end}
.grid.top{align-items:start}
.hint{color:var(--mut);font-size:12px;margin-top:3px;min-height:1.2em}
label{display:block;color:var(--mut);font-size:12px;margin:8px 0 3px}
input,select,textarea{width:100%;background:#111722;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:7px 9px;font:inherit}
textarea{font-family:ui-monospace,Consolas,monospace;font-size:13px}
pre{background:#0c1118;border:1px solid var(--line);border-radius:6px;padding:12px;overflow:auto;white-space:pre-wrap;font-size:12.5px}
.tag{display:inline-block;padding:1px 7px;border-radius:10px;background:#2b3648;font-size:12px}
.tag.windows{background:#1f3b63}.tag.linux{background:#3b3a1f}
.st-ok{color:var(--ok)}.st-err{color:var(--err)}.st-run{color:var(--warn)}.st-warn{color:var(--warn)}
.tag.sec{background:#5a1d1d}
dialog{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:16px 18px;width:min(720px,94vw)}
dialog::backdrop{background:rgba(0,0,0,.6)}table.dlg{border-radius:0}table.dlg td{padding:6px 9px}
label.plain{display:inline;color:var(--text);font-size:14px;margin:0;cursor:pointer}
input[type=checkbox],input[type=radio]{width:auto}
.when{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin-top:12px}
.flash.plan{background:#1d2f4d}button.small{padding:2px 8px;font-size:12px}
.spin{display:inline-block;animation:spin 1.2s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
</style></head><body>
{% if session.user %}<header><b>&#9881; Ansible-UI</b><nav>
<a href="/">Maschinen</a>{% if admin %}<a href="/playbooks">Playbooks</a>{% endif %}<a href="/laeufe">Läufe</a>{% if admin %}<a href="/einstellungen">Einstellungen</a><a href="/benutzer">Benutzer</a>{% endif %}</nav>
<span class="sp"></span><span class="mut">{{ session.user }}{% if not admin %} <a href="/passwort" class="small">Passwort</a>{% endif %}</span><a href="/logout">Abmelden</a></header>{% endif %}
<main>{% for cat,m in get_flashed_messages(with_categories=true) %}<div class="flash {{cat}}">{{m}}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>"""

LOGIN = """{% extends "base.html" %}{% block title %}Anmelden{% endblock %}{% block body %}
<div class="card" style="max-width:360px;margin:80px auto"><h1>Ansible-UI</h1>
<form method="post"><label>Benutzer</label><input name="user" autofocus>
<label>Passwort</label><input name="password" type="password">
<p><button class="acc">Anmelden</button></p></form></div>{% endblock %}"""

INDEX = """{% extends "base.html" %}{% block title %}Maschinen{% endblock %}
{% block head %}{% if running %}<script>setTimeout(function r(){if(document.querySelector('dialog[open]'))return setTimeout(r,5000);location.reload()},5000)</script>{% endif %}{% endblock %}
{% block body %}<div class="fit"><h1>Maschinen <span class="mut small">({{ rows|length }})</span></h1>
<div class="bar"><span class="mut small" style="width:70px">Standort</span>
 <a class="btn {{ 'acc' if not loc }}" href="{{ qs(gruppe=grp, status=stat, updates=updf) }}">Alle</a>
 {% for l in locations %}<a class="btn {{ 'acc' if loc==l }}" href="{{ qs(gruppe=grp, standort=l, status=stat, updates=updf) }}">{{ l }} <span class="mut small">{{ counts[l] }}</span></a>{% endfor %}
</div>
<div class="bar"><span class="mut small" style="width:70px">System</span>
 <a class="btn {{ 'acc' if not grp }}" href="{{ qs(standort=loc, status=stat, updates=updf) }}">Alle</a>
 {% for g in groups %}<a class="btn {{ 'acc' if grp==g }}" href="{{ qs(gruppe=g, standort=loc, status=stat, updates=updf) }}">{{ g|capitalize }}</a>{% endfor %}
 <span style="flex:1"></span>
 {% if can.ping %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}">
  <input type="hidden" name="kind" value="ping"><input type="hidden" name="gruppe" value="{{grp}}"><input type="hidden" name="standort" value="{{loc}}"><input type="hidden" name="status" value="{{stat}}"><input type="hidden" name="updates" value="{{updf}}"><button>{{ 'Alle' if not (grp or loc or stat or updf) else 'Auswahl' }} pingen</button></form>{% endif %}
 {% if can.facts %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}">
  <input type="hidden" name="kind" value="facts"><input type="hidden" name="gruppe" value="{{grp}}"><input type="hidden" name="standort" value="{{loc}}"><input type="hidden" name="status" value="{{stat}}"><input type="hidden" name="updates" value="{{updf}}"><button>Info Device {{ 'alle' if not (grp or loc or stat or updf) else 'Auswahl' }}</button></form>{% endif %}
 {% if can.upd_check %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}">
  <input type="hidden" name="kind" value="updates"><input type="hidden" name="gruppe" value="{{grp}}"><input type="hidden" name="standort" value="{{loc}}"><input type="hidden" name="status" value="{{stat}}"><input type="hidden" name="updates" value="{{updf}}"><button title="sucht nur, installiert nichts">Updates {{ 'aller' if not (grp or loc or stat or updf) else 'der Auswahl' }} prüfen</button></form>
 <form class="inl" method="post" action="/massen"><input type="hidden" name="csrf" value="{{csrf}}">
  <input type="hidden" name="kind" value="check"><input type="hidden" name="gruppe" value="{{grp}}"><input type="hidden" name="standort" value="{{loc}}"><input type="hidden" name="status" value="{{stat}}"><input type="hidden" name="updates" value="{{updf}}"><button title="Probelauf der Update-Playbooks – installiert nichts">Update Check {{ 'alle' if not (grp or loc or stat or updf) else 'Auswahl' }}</button></form>
 {% endif %}{% if can.upd_install %}<button type="button" class="acc" {{ 'disabled' if not upd_rows }} title="Maschinen auswählen, sofort oder geplant" onclick="document.getElementById('dlg-upd').showModal();updCount()">Update {{ 'alle' if not (grp or loc or stat or updf) else 'Auswahl' }} ({{ n_upd }})</button>
 {% endif %}{% if reboot_rows and can.reboot %}<button type="button" class="danger" title="Reihenfolge festlegen – streng nacheinander" onclick="document.getElementById('dlg-rb').showModal();rbUpd()">Neustart {{ 'alle' if not (grp or loc or stat or updf) else 'Auswahl' }} ({{ n_reboot }})</button>{% endif %}
 {% if admin %}<a class="btn acc" href="/maschine/neu{{ ('?standort=' ~ loc) if loc }}">+ Maschine</a>{% endif %}
</div>
{% for pl in plans %}<div class="flash plan">{% if can.plan %}<form class="inl" method="post" action="/geplant/loeschen" style="float:right;margin-left:12px"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="id" value="{{ pl.id }}"><button class="small" onclick="return confirm('Geplanten Lauf {{ pl.when }} entfernen?')">{{ 'Löschen' if pl.status == 'geplant' else 'Ausblenden' }}</button></form>{% endif %}
 &#128339; {% if pl.status == 'geplant' %}Geplant{% elif pl.status == 'gestartet' %}Gestartet{% else %}<span class="st-err">Verpasst</span>{% endif %}: {{ 'Neustart' if pl.kind == 'reboot' else 'Update' }} am <b>{{ pl.when[8:10] }}.{{ pl.when[5:7] }}.{{ pl.when[:4] }} um {{ pl.when[11:] }}</b> – {{ pl.names|length }} Maschine(n){% if pl.kind == 'reboot' %}{% if pl.stages %} in {{ pl.stages|length }} Stufe(n){% else %} nacheinander{% endif %}{% if pl.wait %}, je {{ pl.wait }} min Pause{% endif %}{% endif %}
 <div class="small mut">{% if pl.kind == 'reboot' and pl.stages %}{% for st in pl.stages %}{% for n in st %}{{ disp.get(n, n) }}{% if not loop.last %} + {% endif %}{% endfor %}{% if not loop.last %} → {% endif %}{% endfor %}{% else %}{% for n in pl.names %}{{ disp.get(n, n) }}{% if not loop.last %}{{ ' → ' if pl.kind == 'reboot' else ', ' }}{% endif %}{% endfor %}{% endif %}{% if pl.status == 'verpasst' %} · nicht ausgeführt, Container war zum Zeitpunkt nicht aktiv{% endif %}</div></div>{% endfor %}
<dialog id="dlg-rb"><form method="post" action="/neustart" onsubmit="return rbSubmit(this)"><input type="hidden" name="csrf" value="{{csrf}}">
<h2 style="margin:0 0 4px;color:var(--text)">Neustart – Reihenfolge in Stufen</h2>
<div class="small mut" style="margin-bottom:8px">Die Zahl ist die <b>Stufe</b>: gleiche Zahl = gleichzeitig. Die nächste Stufe startet erst, wenn <b>alle</b> Maschinen der vorigen vollständig wieder laufen
(Linux: <code>systemctl is-system-running</code> = running, Windows: keine Dienste mehr im Start). Kommt eine nicht zurück, bricht die Kette ab.</div>
<div style="max-height:46vh;overflow:auto;border:1px solid var(--line);border-radius:8px"><table class="dlg" id="rb-list">
{% for r in reboot_rows %}<tr data-n="{{ r.name }}"><td style="width:1%"><input type="checkbox" class="rbh" name="host" value="{{ r.name }}" id="rb-{{ loop.index }}" {{ '' if r.no_mass else 'checked' }} onchange="rbUpd()"></td>
<td style="width:1%"><input type="number" class="rbnum" name="st_{{ r.name }}" min="1" style="width:58px;padding:4px 6px" title="Stufe – gleiche Zahl = gleichzeitig" onchange="rbSort()"></td>
<td><label for="rb-{{ loop.index }}" class="plain"><b>{{ r.display or r.name }}</b>{% if r.no_mass %} <span class="st-warn small">nur einzeln</span>{% endif %}</label>{% if r.location %}<div class="mut small">&#128205; {{ r.location }}</div>{% endif %}</td>
<td><span class="tag {{ r.group }}">{{ r.group }}</span></td>
<td style="white-space:nowrap;width:1%"><button type="button" class="small" title="eine Stufe früher" onclick="rbMove(this,-1)">&#9650;</button> <button type="button" class="small" title="eine Stufe später" onclick="rbMove(this,1)">&#9660;</button></td></tr>{% endfor %}
</table></div><div class="small" id="rb-sum" style="margin-top:8px"></div>
<div class="when"><label class="plain">zwischen den Stufen noch <input type="number" name="wait" value="0" min="0" max="120" style="width:70px"> min warten</label></div>
<div class="when"><label class="plain"><input type="radio" name="mode" value="jetzt" checked onchange="rbUpd()"> sofort starten</label>
{% if can.plan %}<label class="plain"><input type="radio" name="mode" value="plan" id="rb-plan" onchange="rbUpd()"> geplant am</label>{% else %}<input type="radio" id="rb-plan" hidden disabled>{% endif %}
<input type="datetime-local" name="when" id="rb-when" {{ '' if can.plan else 'hidden' }} min="{{ now_min }}" style="width:auto" onfocus="document.getElementById('rb-plan').checked=true;rbUpd()" onchange="document.getElementById('rb-plan').checked=true;rbUpd()"></div>
<p style="text-align:right;margin:12px 0 0"><button type="button" onclick="this.closest('dialog').close()">Abbrechen</button> <button class="danger" id="rb-go">Neu starten</button></p>
</form></dialog>
<script>
function rbRows(){return [].slice.call(document.querySelectorAll('#rb-list tr'))}
function rbMove(b,d){var n=b.closest('tr').querySelector('.rbnum'),c=b.closest('tr').querySelector('.rbh');if(!c.checked)return;n.value=Math.max(1,(parseInt(n.value,10)||1)+d);rbSort()}
function rbSort(){var rows=rbRows(),tb=rows.length?rows[0].parentNode:null;if(!tb)return;
 rows.sort(function(a,b){var ca=a.querySelector('.rbh').checked,cb=b.querySelector('.rbh').checked;if(ca!==cb)return ca?-1:1;
  return (parseInt(a.querySelector('.rbnum').value,10)||999)-(parseInt(b.querySelector('.rbnum').value,10)||999)});
 rows.forEach(function(r){tb.appendChild(r)});rbUpd()}
function rbStages(){var st={};rbRows().forEach(function(tr){var c=tr.querySelector('.rbh');if(!c.checked)return;var k=parseInt(tr.querySelector('.rbnum').value,10)||1;
 (st[k]=st[k]||[]).push(tr.querySelector('b').textContent)});return Object.keys(st).map(Number).sort(function(a,b){return a-b}).map(function(k){return st[k]})}
function rbUpd(){var mx=0;rbRows().forEach(function(tr){var c=tr.querySelector('.rbh'),n=tr.querySelector('.rbnum');if(c.checked&&n.value)mx=Math.max(mx,parseInt(n.value,10)||0)});
 var k=0;rbRows().forEach(function(tr){var c=tr.querySelector('.rbh'),n=tr.querySelector('.rbnum');if(c.checked){k++;if(!n.value)n.value=++mx}else n.value='';n.disabled=!c.checked;tr.style.opacity=c.checked?1:.55});
 var sts=rbStages();document.getElementById('rb-sum').innerHTML=sts.length?sts.map(function(s,i){return '<b>Stufe '+(i+1)+':</b> '+s.join(', ')}).join(' &nbsp;→&nbsp; '):'';
var pl=document.getElementById('rb-plan').checked,b=document.getElementById('rb-go');b.textContent=(pl?'Planen':'Jetzt neu starten')+' ('+k+(sts.length>1?' in '+sts.length+' Stufen':'')+')';b.disabled=!k}
function rbSubmit(f){var sts=rbStages();if(!sts.length)return false;
 if(document.getElementById('rb-plan').checked){var w=document.getElementById('rb-when').value;if(!w){alert('Bitte Datum und Uhrzeit angeben.');return false}
  if(new Date(w)<=new Date()){alert('Der Zeitpunkt liegt in der Vergangenheit.');return false}return true}
 return confirm('Jetzt in Stufen neu starten?\\n\\n'+sts.map(function(s,i){return 'Stufe '+(i+1)+': '+s.join(', ')}).join('\\n'))}
</script>
<dialog id="dlg-upd"><form method="post" action="/massen" onsubmit="return updSubmit(this)"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="kind" value="update"><input type="hidden" name="pick" value="1">
<h2 style="margin:0 0 4px;color:var(--text)">Updates installieren</h2>
<div class="small mut" style="margin-bottom:8px">Maschinen mit offenen Updates{{ ' (aktueller Filter)' if (grp or loc or stat or updf) }} · ohne Neustart · <a href="#" onclick="updAll(true);return false">alle</a> · <a href="#" onclick="updAll(false);return false">keine</a></div>
<div style="max-height:52vh;overflow:auto;border:1px solid var(--line);border-radius:8px"><table class="dlg">
{% for r in upd_rows %}{% set u = r.st.upd %}<tr><td style="width:1%"><input type="checkbox" class="updh" name="host" value="{{ r.name }}" id="uh-{{ loop.index }}" {{ '' if r.no_mass else 'checked' }} onchange="updCount()"></td>
<td><label for="uh-{{ loop.index }}" class="plain"><b>{{ r.display or r.name }}</b>{% if r.no_mass %} <span class="st-warn small">nur einzeln</span>{% endif %}</label><div class="mut small">&#128205; {{ r.location }}</div></td>
<td><span class="tag {{ r.group }}">{{ r.group }}</span></td>
<td class="small" style="white-space:nowrap"><span class="st-warn">{{ u.count }} Update{{ 's' if u.count != 1 }}</span>{% if u.security %}<div class="st-err">{{ u.security }} Sicherheit</div>{% endif %}</td></tr>{% endfor %}
</table></div>
<div class="when"><label class="plain"><input type="radio" name="mode" value="jetzt" checked onchange="updCount()"> sofort starten</label>
{% if can.plan %}<label class="plain"><input type="radio" name="mode" value="plan" id="upd-plan" onchange="updCount()"> geplant am</label>{% else %}<input type="radio" id="upd-plan" hidden disabled>{% endif %}
<input type="datetime-local" name="when" id="upd-when" {{ '' if can.plan else 'hidden' }} min="{{ now_min }}" style="width:auto" onfocus="document.getElementById('upd-plan').checked=true;updCount()" onchange="document.getElementById('upd-plan').checked=true;updCount()"></div>
<div class="hint">Geplante Läufe stehen oben auf der Startseite und lassen sich dort wieder löschen.</div>
<p style="text-align:right;margin:12px 0 0"><button type="button" onclick="this.closest('dialog').close()">Abbrechen</button> <button class="acc" id="upd-go">Installieren</button></p>
</form></dialog>
<script>
function updAll(v){document.querySelectorAll('.updh').forEach(function(c){c.checked=v});updCount()}
function updCount(){var n=document.querySelectorAll('.updh:checked').length,pl=document.getElementById('upd-plan').checked,b=document.getElementById('upd-go');
 b.textContent=(pl?'Planen':'Jetzt installieren')+' ('+n+')';b.disabled=!n}
function updSubmit(f){var n=f.querySelectorAll('.updh:checked').length;if(!n)return false;
 if(document.getElementById('upd-plan').checked){var w=document.getElementById('upd-when').value;
  if(!w){alert('Bitte Datum und Uhrzeit angeben.');return false}
  if(new Date(w)<=new Date()){document.getElementById('upd-when').setCustomValidity('Zeitpunkt liegt in der Vergangenheit');document.getElementById('upd-when').reportValidity();document.getElementById('upd-when').setCustomValidity('');return false}
  return true}
 return confirm('Updates jetzt auf '+n+' Maschine(n) installieren (ohne Neustart)?')}
</script>
{% if running %}<div class="flash ok">Läuft gerade: {% for r in running %}<a href="/laeufe/{{r.id}}">{{ r.title }}</a>{% if not loop.last %}, {% endif %}{% endfor %} – Seite aktualisiert sich selbst.</div>{% endif %}
<table class="auto"><tr><th><select class="thsel{{ ' on' if stat }}" onchange="location=this.value" title="nach Status filtern">
 <option value="{{ qs(gruppe=grp, standort=loc, updates=updf) }}">Status: alle</option>
 {% for k, v in slabels.items() %}<option value="{{ qs(gruppe=grp, standort=loc, status=k, updates=updf) }}" {{ 'selected' if stat==k }}>{{ v }} ({{ scounts[k] }})</option>{% endfor %}
</select></th><th>Name</th><th>Standort</th><th>Gruppe</th><th>Adresse</th><th style="min-width:230px">Betriebssystem</th><th style="white-space:nowrap;min-width:90px">CPU / RAM</th><th>Laufzeit</th><th><select class="thsel{{ ' on' if updf }}" onchange="location=this.value" title="nach Updates filtern">
 <option value="{{ qs(gruppe=grp, standort=loc, status=stat) }}">Updates: alle</option>
 {% for k, v in ulabels.items() %}<option value="{{ qs(gruppe=grp, standort=loc, status=stat, updates=k) }}" {{ 'selected' if updf==k }}>{{ v }} ({{ ucounts[k] }})</option>{% endfor %}
</select></th><th style="white-space:nowrap">Letzter Kontakt</th><th>Aktionen</th></tr>
{% for r in rows %}<tr class="{{ '' if r.enabled else 'off' }}{{ ' locstart' if not loop.first and r.location != loop.previtem.location }}">
<td>{% if not r.enabled %}<span class="dot"></span><span class="mut small">inaktiv</span>
 {% elif r.st.ping_time %}<span class="dot {{ 'ok' if r.st.ping_ok else 'err' }}"></span><span class="small {{ 'st-ok' if r.st.ping_ok else 'st-err' }}">{{ 'erreichbar' if r.st.ping_ok else 'Fehler' }}</span>
 {% else %}<span class="dot"></span><span class="mut small">unbekannt</span>{% endif %}</td>
<td><a href="/maschine/{{ r.name }}"><b>{{ r.display or r.name }}</b></a>{% if r.notes %}<div class="mut small">{{ r.notes }}</div>{% endif %}</td>
<td style="white-space:nowrap">&#128205; {{ r.location }}</td>
<td><span class="tag {{ r.group }}">{{ r.group }}</span></td>
<td>{% if not r.addrs %}–{% elif r.addrs|length == 1 %}{{ r.addrs[0] }}{% if r.port %}<span class="mut small">:{{ r.port }}</span>{% endif %}
 {% else %}{% set via = r.st.via %}{% for a in r.addrs %}<div class="{{ '' if via and via.ok and via.addr == a else 'mut small' }}">{{ a }}{% if loop.first and r.port %}<span class="mut small">:{{ r.port }}</span>{% endif %}{% if via and via.ok and via.addr == a %} <span class="st-ok small" title="zuletzt erreicht {{ via.time }}">&#10003; aktiv</span>{% endif %}</div>{% endfor %}
 {% if via and not via.ok %}<div class="st-err small">keine Adresse erreichbar ({{ via.time[11:16] }})</div>{% endif %}{% endif %}<div class="mut small">{{ r.prof }}{% if r.user %} · {{ r.user }}{% endif %}{% if not r.prof_own %} <i>(Standard)</i>{% endif %}</div></td>
<td style="min-width:230px">{{ (r.sum.os or '–')|replace('Microsoft ', '') }}{% if r.sum.kernel %}<div class="mut small">{{ r.sum.kernel }}</div>{% endif %}</td>
<td style="white-space:nowrap">{% if r.sum.cpu %}{{ r.sum.cpu }} vCPU<div class="mut small">{{ r.sum.ram }}</div>{% else %}–{% endif %}</td>
<td>{{ r.sum.uptime or '–' }}</td>
<td class="small" style="white-space:nowrap"><div style="display:flex;gap:12px;align-items:center"><div>{% if r.lastfail and not r.run %}<div style="margin-bottom:4px;white-space:normal;max-width:260px"><a class="st-err" href="/laeufe/{{ r.lastfail.id }}">&#10007; {{ r.lastfail.what }} {{ r.lastfail.time }} {{ r.lastfail.verb }}</a>{% if r.lastfail.why and r.lastfail.why != 'abgebrochen' %}<div class="st-err" style="opacity:.8">{{ r.lastfail.why }}</div>{% endif %}</div>{% endif %}{% if r.run %}<div style="margin-bottom:4px"><a class="st-run" href="/laeufe/{{ r.run.id }}" title="seit {{ r.run.start }}"><span class="spin">&#10227;</span> {{ r.run.what }}…</a></div>{% endif %}{% set u = r.st.upd %}{% if not u %}<span class="mut">–</span>
 {% elif not u.ok %}<span class="st-err" title="{{ u.msg }}">Prüfung fehlgeschlagen</span>
 {% elif not u.count %}<span class="st-ok">&#10004; aktuell</span>
 {% else %}<a class="st-warn" href="/maschine/{{ r.name }}#updates">{{ u.count }} Update{{ 's' if u.count != 1 }}</a>{% if u.security %}<div class="st-err">davon {{ u.security }} Sicherheit</div>{% endif %}{% endif %}
 {% if u and u.reboot %}<div class="st-warn">Neustart nötig</div>{% endif %}
 {% if u and u.release and u.release.new %}<div style="color:#7cb7ff" title="aktuell: {{ u.release.cur }}">&#11014; {{ u.release.new }} verfügbar</div>{% endif %}
 {% if u %}<div class="mut" title="{{ u.stale or '' }}">{{ u.time[:16] }}{% if u.stale %} *{% endif %}</div>{% endif %}
</div>
 {% set pb = 'updates-installieren-' ~ r.group ~ '.yml' %}{% if r.enabled and r.address and pb in pbs and (can.upd_check or can.upd_install or can.reboot) %}
 <div style="white-space:nowrap;text-align:center"><div><form class="inl" method="post" action="/playbook/start"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="playbook" value="{{ pb }}"><input type="hidden" name="target" value="{{ r.name }}"><input type="hidden" name="check" value="1"><button title="Probelauf: zeigt, was installiert würde" {{ '' if can.upd_check else 'hidden' }}>Update Check</button></form>
 {% if u and u.ok and u.count and can.upd_install %}<form class="inl" method="post" action="/playbook/start" onsubmit="return confirm('{{ u.count }} Update(s) auf {{ r.display or r.name }} jetzt installieren?{{ ' (Windows: kann dauern, Programme vorher schließen)' if r.group == 'windows' }}')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="playbook" value="{{ pb }}"><input type="hidden" name="target" value="{{ r.name }}"><button class="acc" title="Updates installieren (ohne Neustart)">Update</button></form>{% endif %}
 {% if u and u.reboot and can.reboot %}<form class="inl" method="post" action="/neustart" onsubmit="return confirm('{{ r.display or r.name }} jetzt neu starten?{{ ' ACHTUNG: Docker-Host bzw. nur-einzeln-Maschine – dabei sind alle Dienste darauf weg, auch diese Seite.' if r.no_mass }}')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="target" value="{{ r.name }}"><button class="danger" title="Maschine neu starten">Neustart</button></form>{% endif %}
 {% if admin and u and u.release and u.release.new and r.group == 'linux' and 'pve' not in (r.sum.kernel or '') %}<form class="inl" method="post" action="/upgrade" onsubmit="return confirm('Distributions-Upgrade von {{ r.display or r.name }} auf {{ u.release.new }} starten?\\n\\nVORHER einen Snapshot bzw. ein Backup machen!\\nDauert 20–60 Minuten, die Maschine startet dabei neu und ist zeitweise nicht erreichbar.')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="target" value="{{ r.name }}"><button style="background:#1f3b63;border-color:#2f5b93" title="auf {{ u.release.new }} aktualisieren">Upgrade</button></form>{% endif %}</div>{% if r.no_mass %}<div class="mut" title="wird bei „Update alle“ ausgelassen">nur einzeln</div>{% endif %}</div>{% endif %}</div></td>
<td class="small" style="white-space:nowrap" title="{{ r.st.ping_time or '' }}">{% if r.st.ping_time %}{{ r.st.ping_time[8:10] }}.{{ r.st.ping_time[5:7] }}. {{ r.st.ping_time[11:16] }}{% else %}–{% endif %}{% if r.st.ping_msg and not r.st.ping_ok %}<div class="st-err" style="white-space:normal;max-width:220px">{{ r.st.ping_msg }}</div>{% endif %}</td>
<td style="white-space:nowrap">{% if r.enabled and r.address %}
 {% if can.ping %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="kind" value="ping"><input type="hidden" name="target" value="{{ r.name }}"><button>Ping</button></form>{% endif %}
 {% if can.facts %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="kind" value="facts"><input type="hidden" name="target" value="{{ r.name }}"><button>Info</button></form>{% endif %}
 {% if can.upd_check %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="kind" value="updates"><input type="hidden" name="target" value="{{ r.name }}"><button title="Updates suchen (installiert nichts)">Updates</button></form>{% endif %}{% endif %}
 <a class="btn" href="/maschine/{{ r.name }}">Details</a></td></tr>{% endfor %}
</table></div>{% endblock %}"""

MACHINE = """{% extends "base.html" %}{% block title %}{{ (h.display or name) if name else 'Neue Maschine' }}{% endblock %}{% block body %}
<h1>{{ (h.display or name) if name else 'Neue Maschine' }} {% if name %}{% if h.display %}<span class="mut small">{{ name }}</span> {% endif %}<span class="tag {{h.group}}">{{h.group}}</span> <span class="tag">&#128205; {{ h.location }}</span>{% endif %}</h1>
{% if name %}<div class="grid top">
<div class="card"><h2 style="margin-top:0">Status</h2>
 {% if st.ping_time %}<span class="dot {{ 'ok' if st.ping_ok else 'err' }}"></span>{{ 'erreichbar' if st.ping_ok else st.ping_msg }}<div class="mut small">{{ st.ping_time }}</div>{% else %}<span class="mut">noch nie geprüft</span>{% endif %}
 <div class="mut small">Info Device: {{ st.facts_time or 'noch keine' }}</div>
 {% if st.via %}<div class="small {{ 'mut' if st.via.ok else 'st-err' }}">{{ ('zuletzt erreicht über ' ~ st.via.addr) if st.via.ok else 'keine der Adressen erreichbar' }} ({{ st.via.time }})</div>{% endif %}
 <p>{% if h.enabled and h.address %}
 {% if can.ping %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="kind" value="ping"><input type="hidden" name="target" value="{{ name }}"><button>Ping</button></form>{% endif %}
 {% if can.facts %}<form class="inl" method="post" action="/aktion"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="kind" value="facts"><input type="hidden" name="target" value="{{ name }}"><button>Info Device</button></form>{% endif %}{% endif %}</p></div>
<div class="card"><h2 style="margin-top:0">System</h2>{% if admin %}<div class="small mut">Zugang: {{ plabel }}</div>{% endif %}{% if s %}
 <div>{{ s.os }}</div><div class="mut small">{{ s.hostname }}</div>
 <div class="small">Kernel {{ s.kernel }} · {{ s.arch }} · {{ s.virt }}</div>
 <div class="small">{{ s.cpu }} vCPU · {{ s.ram }} RAM · läuft seit {{ s.uptime }}</div>
 <div class="small mut">IPs: {{ s.ips }}</div>{% else %}<span class="mut">Noch keine Infos – „Info Device“ drücken.</span>{% endif %}</div>
{% if can.upd_check or can.upd_install %}<div class="card"><h2 style="margin-top:0">{{ 'Playbook ausführen' if admin else 'Updates installieren' }}</h2>
 {% if playbooks and h.enabled and h.address %}<form method="post" action="/playbook/start"><input type="hidden" name="csrf" value="{{csrf}}">
 <input type="hidden" name="target" value="{{ name }}"><select name="playbook">{% for pb in playbooks %}<option {{ 'selected' if pb == pb_default }}>{{pb}}</option>{% endfor %}</select>
 {% if can.upd_install %}<label><input type="checkbox" name="check" value="1" style="width:auto" checked> nur Probelauf (--check)</label>{% else %}<input type="hidden" name="check" value="1"><div class="mut small">nur Probelauf (--check) erlaubt</div>{% endif %}
 <p><button class="acc">Starten</button></p></form>{% else %}<span class="mut">{{ 'Maschine inaktiv oder ohne Adresse.' if playbooks else 'Kein Playbook für ' ~ h.group ~ ' vorhanden.' }}</span>{% endif %}</div>{% endif %}
</div>
<div class="card" id="updates"><h2 style="margin-top:0">Updates</h2>{% set u = st.upd %}
 {% if not u %}<span class="mut">Noch nicht geprüft.</span>
 {% elif not u.ok %}<span class="st-err">Prüfung fehlgeschlagen: {{ u.msg }}</span><div class="mut small">{{ u.time }}</div>
 {% else %}<div>{% if not u.count %}<span class="st-ok">&#10004; Alles aktuell</span>{% else %}<b class="st-warn">{{ u.count }} Update{{ 's' if u.count != 1 }} verfügbar</b>{% if u.security %} · <span class="st-err">davon {{ u.security }} Sicherheit</span>{% endif %}{% endif %}
 {% if u.reboot %} · <span class="st-warn">Neustart nötig</span>{% endif %}</div>
 <div class="mut small">Geprüft {{ u.time }} über {{ u.pm }}{% if u.stale %} · letzter Versuch {{ u.stale }}{% endif %}</div>
 {% if u.release %}<div class="small" style="margin-top:4px">Version: {{ u.release.cur or s.os }}{% if u.release.new %} · <b style="color:#7cb7ff">&#11014; {{ u.release.new }} verfügbar</b> <span class="mut">(Distributions-Upgrade, nicht in den normalen Updates enthalten)</span>
 {% if admin and h.group == 'linux' and 'pve' not in (s.kernel or '') and h.enabled and h.address %}<form class="inl" method="post" action="/upgrade" onsubmit="return confirm('Distributions-Upgrade auf {{ u.release.new }} starten?\\n\\nVORHER einen Snapshot bzw. ein Backup machen!\\nDauert 20–60 Minuten, die Maschine startet dabei neu.')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="target" value="{{ name }}"><button style="background:#1f3b63;border-color:#2f5b93">Upgrade auf {{ u.release.new }}</button></form>{% endif %}{% else %} · <span class="st-ok">neueste Version</span>{% endif %}</div>{% endif %}
 {% if u.warn %}<div class="st-warn small">{{ u.warn }}</div>{% endif %}
 {% if (u.get('items') or []) %}<details {{ 'open' if (u.get('items') or [])|length <= 15 }} style="margin-top:8px"><summary class="mut">Liste ({{ (u.get('items') or [])|length }})</summary>
 <table style="margin-top:6px"><tr><th>Paket / Update</th><th>Installiert</th><th>Neu</th><th></th></tr>
 {% for i in (u.get('items') or []) %}<tr><td>{{ i.name }}</td><td class="small mut">{{ i.from }}</td><td class="small">{{ i.to }}</td><td>{% if i.sec %}<span class="tag sec">Sicherheit</span>{% endif %}</td></tr>{% endfor %}</table></details>{% endif %}
 {% endif %}
 {% if h.enabled and h.address and can.upd_check %}<form method="post" action="/aktion" style="margin-top:10px"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="kind" value="updates"><input type="hidden" name="target" value="{{ name }}"><button>Updates prüfen</button> <span class="mut small">sucht nur – installiert wird mit einem Playbook (z. B. updates-installieren-{{ h.group }}.yml)</span></form>{% endif %}
</div>{% endif %}
{% if admin %}<div class="card"><h2 style="margin-top:0">{{ 'Bearbeiten' if name else 'Anlegen' }}</h2>
<form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><div class="grid">
 <div><label>Anzeigename (frei wählbar)</label><input name="display" value="{{ h.display or h.name }}" placeholder="z. B. Webserver – Büro" required></div>
 <div><label>Technischer Name für Ansible {{ '' if name else '(leer = automatisch)' }}</label><input name="name" value="{{ h.name }}" placeholder="wird aus dem Anzeigenamen gebildet" pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,62}" title="nur Buchstaben, Ziffern, Punkt, Minus, Unterstrich"></div>
 <div><label>Adresse(n) – IP oder DNS, mehrere mit Komma (z. B. LAN, WLAN)</label><input name="address" value="{{ h.address }}" placeholder="192.168.1.10, 192.168.1.11"></div>
 <div><label>Gruppe</label><select name="group">{% for g in groups %}<option {{ 'selected' if h.group==g }}>{{g}}</option>{% endfor %}</select></div>
 <div><label>Standort</label><select name="location">{% for l in locations %}<option {{ 'selected' if h.location==l }}>{{l}}</option>{% endfor %}</select></div>
 <div><label>Zugangsprofil</label><select name="profile"><option value="">Standard der Gruppe</option>
  {% for x in profiles.profiles %}<option value="{{x.id}}" {{ 'selected' if h.profile==x.id }}>{{ x.name }} ({{ x.type }})</option>{% endfor %}</select></div>
 <div><label>Benutzer (leer = aus dem Profil)</label><input name="user" value="{{ h.user }}"></div>
 <div><label>Port (SSH 22 / WinRM 5985)</label><input name="port" type="number" value="{{ h.port }}"></div>
 <div><label>Aktiv</label><input type="checkbox" name="enabled" value="1" style="width:auto" {{ 'checked' if h.enabled }}></div>
 <div><label><input type="checkbox" name="no_mass" value="1" style="width:auto" {{ 'checked' if h.no_mass }}> Nicht bei „Update alle“</label><div class="hint">nur einzeln aktualisieren (z. B. Docker-Host, Domänencontroller)</div></div>
</div><label>Notiz</label><input name="notes" value="{{ h.notes }}">
<p><button class="acc">Speichern</button></p></form>
{% if name %}<form method="post" onsubmit="return confirm('{{name}} wirklich löschen?')"><input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="delete" value="1"><button class="danger">Maschine löschen</button></form>{% endif %}</div>{% endif %}
{% if name and runs %}<h2>Letzte Läufe</h2><table><tr><th>Start</th><th>Lauf</th><th>Status</th></tr>
{% for r in runs %}<tr><td class="small">{{r.start}}</td><td><a href="/laeufe/{{r.id}}">{{r.title}}</a></td>
<td class="{{ 'st-ok' if r.status=='ok' else ('st-run' if r.status=='laeuft' else 'st-err') }}">{{r.status}}</td></tr>{% endfor %}</table>{% endif %}
{% if f %}<h2>Alle Device-Infos</h2><details><summary class="mut">anzeigen ({{ f|length }} Einträge)</summary><pre>{{ facts_json }}</pre></details>{% endif %}
{% endblock %}"""

PLAYBOOKS = """{% extends "base.html" %}{% block title %}Playbooks{% endblock %}{% block body %}
<h1>Playbooks</h1><div class="grid top" style="grid-template-columns:280px 1fr">
<div class="card"><h2 style="margin-top:0">Dateien</h2>
{% for i in items %}<div><a href="/playbooks?datei={{i}}">{{ i }}</a></div>{% else %}<span class="mut">keine</span>{% endfor %}
<p><a class="btn" href="/playbooks?datei=neu.yml">+ Neues Playbook</a></p></div>
<div class="card">{% if edit %}<form method="post"><input type="hidden" name="csrf" value="{{csrf}}">
<label>Dateiname</label><input name="filename" value="{{ edit }}">
<label>Inhalt (YAML)</label><textarea name="content" rows="26">{{ content }}</textarea>
<p><button class="acc">Speichern</button></p></form>
{% if edit in items %}<form method="post" action="/playbook/start"><input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="playbook" value="{{edit}}"><div class="bar"><span class="mut">Ausführen auf</span>
<select name="target" style="width:auto"><option value="all">alle</option>{% for g in groups %}<option>{{g}}</option>{% endfor %}</select>
<label style="margin:0"><input type="checkbox" name="check" value="1" style="width:auto" checked> Probelauf</label>
<button class="acc">Starten</button></div></form>
<form method="post" onsubmit="return confirm('{{edit}} löschen?')"><input type="hidden" name="csrf" value="{{csrf}}">
<input type="hidden" name="filename" value="{{edit}}"><input type="hidden" name="delete" value="1"><button class="danger">Löschen</button></form>{% endif %}
{% else %}<span class="mut">Links ein Playbook wählen oder ein neues anlegen. Einzelne Maschinen startest du auf ihrer Detailseite.</span>{% endif %}</div></div>{% endblock %}"""

RUNS = """{% extends "base.html" %}{% block title %}Läufe{% endblock %}
{% block head %}<meta http-equiv="refresh" content="10">{% endblock %}{% block body %}
<h1>Läufe</h1><table><tr><th>Start</th><th>Ende</th><th>Lauf</th><th>Ziel</th><th>Status</th></tr>
{% for r in runs %}<tr><td class="small">{{r.start}}</td><td class="small">{{r.end or ''}}</td><td><a href="/laeufe/{{r.id}}">{{r.title}}</a></td><td>{{r.target}}</td>
<td class="{{ 'st-ok' if r.status=='ok' else ('st-run' if r.status=='laeuft' else 'st-err') }}">{{r.status}}</td></tr>
{% else %}<tr><td colspan="5" class="mut">noch keine Läufe</td></tr>{% endfor %}</table>{% endblock %}"""

RUN = """{% extends "base.html" %}{% block title %}Lauf{% endblock %}
{% block head %}{% if r.status=='laeuft' %}<meta http-equiv="refresh" content="3">{% endif %}{% endblock %}{% block body %}
<h1>{{ r.title }}</h1><p class="mut">Start {{ r.start }}{% if r.end %} · Ende {{ r.end }}{% endif %} · Status
<b class="{{ 'st-ok' if r.status=='ok' else ('st-run' if r.status=='laeuft' else 'st-err') }}">{{ r.status }}</b></p>
<pre>{{ text or '…' }}</pre><p>{% if back %}<a class="btn acc" href="/maschine/{{ back.name }}">Zurück zu {{ back.display or back.name }}</a> {% endif %}<a class="btn" href="/">Zur Maschinenliste</a></p>{% endblock %}"""

SETTINGS = """{% extends "base.html" %}{% block title %}Einstellungen{% endblock %}{% block body %}
<h1>Einstellungen</h1>
<div class="card"><h2 style="margin-top:0">SSH-Schlüssel für Linux</h2>
<p class="mut">Diesen öffentlichen Schlüssel auf jeder Linux-Maschine beim jeweiligen Benutzer in <code>~/.ssh/authorized_keys</code> eintragen:</p>
<pre>{{ pub }}</pre></div>
<div class="card"><h2 style="margin-top:0">Zugangsprofile</h2>
<p class="mut small">Ein Profil beschreibt, wie Ansible sich anmeldet und wie es Rechte bekommt (z. B. Anmeldung als Benutzer, dann <code>su</code> zu root). Jede Maschine nutzt das Standardprofil ihrer Gruppe oder ein eigenes (auf ihrer Detailseite).</p>
<table><tr><th>Name</th><th>Typ</th><th>Zugang</th><th>Passwörter</th><th>Verwendet von</th><th></th></tr>
{% for x in sec.profiles %}<tr><td><b>{{ x.name }}</b>{% if sec.defaults[x.type]==x.id %} <span class="tag">Standard {{ x.type }}</span>{% endif %}</td>
<td><span class="tag {{x.type}}">{{ x.type }}</span></td><td>{{ label(x) }}</td>
<td class="small">{% if x.password %}Anmeldung ✓ {% endif %}{% if x.become_password %}{{ x.become }} ✓{% endif %}{% if not x.password and not x.become_password %}<span class="mut">–</span>{% endif %}</td>
<td class="small">{{ (used[x.id] or [])|join(', ') or '–' }}</td><td><a class="btn" href="/profil/{{x.id}}">Bearbeiten</a></td></tr>{% endfor %}</table>
<div class="bar" style="margin-top:12px"><a class="btn acc" href="/profil/neu?typ=linux">+ Linux-Profil</a><a class="btn acc" href="/profil/neu?typ=windows">+ Windows-Profil</a></div>
<form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="defaults"><div class="grid">
{% for g in groups %}<div><label>Standardprofil {{ g }}</label><select name="default_{{g}}">{% for x in sec.profiles if x.type==g %}<option value="{{x.id}}" {{ 'selected' if sec.defaults[g]==x.id }}>{{ x.name }}</option>{% endfor %}</select></div>{% endfor %}
<div><button>Standards speichern</button></div></div></form>
<p class="mut small">Passwörter werden nur im Daten-Volume (Datei mit Rechten 0600) gespeichert und nie wieder angezeigt.</p></div>
<div class="card" id="updates"><h2 style="margin-top:0">Update-Prüfung</h2>
<p class="mut small">Sucht auf allen aktiven Maschinen nach Updates und zeigt sie in der Spalte „Updates“ – installiert wird dabei nichts. Ist eine Maschine zur Prüfzeit aus, bleibt das letzte Ergebnis stehen (mit * markiert).</p>
<form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="updates"><div class="grid">
<div><label><input type="checkbox" name="upd_nightly" value="1" style="width:auto" {{ 'checked' if conf.upd_nightly }}> jede Nacht automatisch prüfen</label></div>
<div><label>Uhrzeit</label><input name="upd_time" type="time" value="{{ conf.upd_time }}"></div>
<div><button>Speichern</button></div></div></form>
<p class="mut small">{{ ('Zuletzt automatisch geprüft: ' ~ (conf.upd_last|de_date)) if conf.upd_last else 'Noch keine automatische Prüfung.' }}</p></div>
<div class="card" id="standorte"><h2 style="margin-top:0">Standorte</h2>
<p class="mut small">Reihenfolge = Reihenfolge in der Maschinenliste. Über die Netze (Anfang der IP-Adresse, z. B. <code>192.168.2.</code>) werden neue Maschinen automatisch zugeordnet.</p>
<table><tr><th style="width:70px">Pos.</th><th>Name</th><th>Netze (mit Komma getrennt)</th><th>Maschinen</th><th></th></tr>
{% for l in locs %}{% set i = loop.index0 %}<tr>
<td style="white-space:nowrap">{% if not loop.first %}<form class="inl" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="location"><input type="hidden" name="act" value="up"><input type="hidden" name="idx" value="{{i}}"><button title="nach oben">&#9650;</button></form>{% endif %}
{% if not loop.last %}<form class="inl" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="location"><input type="hidden" name="act" value="down"><input type="hidden" name="idx" value="{{i}}"><button title="nach unten">&#9660;</button></form>{% endif %}</td>
<td colspan="2"><form method="post" style="display:flex;gap:8px"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="location"><input type="hidden" name="act" value="save"><input type="hidden" name="idx" value="{{i}}">
<input name="name" value="{{ l.name }}" style="flex:1"><input name="nets" value="{{ l.nets|join(', ') }}" style="flex:2" placeholder="z. B. 192.168.2."><button>Speichern</button></form></td>
<td>{{ loc_count[l.name] or 0 }}</td>
<td style="white-space:nowrap"><form method="post" style="display:flex;gap:6px" onsubmit="return confirm('Standort {{ l.name }} löschen?')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="location"><input type="hidden" name="act" value="delete"><input type="hidden" name="idx" value="{{i}}">
{% if loc_count[l.name] %}<select name="move_to" style="width:180px;flex:none" title="Maschinen verschieben nach">{% for o in locs if o.name != l.name %}<option>{{ o.name }}</option>{% endfor %}</select>{% else %}<span style="width:180px;flex:none"></span>{% endif %}<button class="danger" style="min-width:190px">{{ 'Löschen + verschieben' if loc_count[l.name] else 'Löschen' }}</button></form></td></tr>{% endfor %}
</table>
<form method="post" style="margin-top:12px"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="location"><input type="hidden" name="act" value="add"><div class="grid">
<div><label>Neuer Standort</label><input name="name" placeholder="z. B. Büro"></div>
<div><label>Netze (optional)</label><input name="nets" placeholder="z. B. 192.168.3."></div>
<div><button class="acc">+ Standort hinzufügen</button></div></div></form></div>
<div class="card" id="passwort"><h2 style="margin-top:0">Admin-Passwort ändern</h2><form method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="password"><div class="grid">
<div><label>Aktuelles Passwort</label><input name="old_password" type="password" autocomplete="current-password" required></div>
<div><label>Neues Passwort (mind. 10 Zeichen)</label><input name="new_password" type="password" autocomplete="new-password" minlength="10" required></div>
<div><label>Neues Passwort wiederholen</label><input name="new_password2" type="password" autocomplete="new-password" minlength="10" required></div>
</div><p><button class="acc">Passwort ändern</button></p></form>
<p class="mut small">{{ ('Zuletzt geändert: ' ~ auth.changed ~ '. ') if auth.changed else 'Es gilt noch das Start-Passwort aus der Umgebungsvariable ADMIN_PASSWORD. ' }}Das Passwort wird nur als Hash im Daten-Volume gespeichert.</p></div>
<p class="mut small">{{ ver }}</p>{% endblock %}"""

PROFILE = """{% extends "base.html" %}{% block title %}Zugangsprofil{% endblock %}{% block body %}
<h1>{{ pr.name or ('Neues ' ~ pr.type ~ '-Profil') }} <span class="tag {{pr.type}}">{{ pr.type }}</span></h1>
<div class="card"><form method="post"><input type="hidden" name="csrf" value="{{csrf}}">
<h2 style="margin-top:0">Anmeldung</h2><div class="grid">
 <div><label>Name des Profils</label><input name="name" value="{{ pr.name }}" required placeholder="z. B. Domäne FIRMA, root über su …"></div>
 <div><label>Benutzer</label><input name="user" value="{{ pr.user }}" placeholder="{{ 'FIRMA\\\\ansible' if pr.type=='windows' else 'z. B. admin' }}"></div>
 {% if pr.type=='linux' %}<div><label>Anmeldung per</label><select name="auth" id="auth" onchange="tg()">
  <option value="key" {{ 'selected' if pr.auth=='key' }}>SSH-Schlüssel der Ansible-UI</option>
  <option value="password" {{ 'selected' if pr.auth=='password' }}>Passwort</option></select></div>{% endif %}
 {% if pr.type=='windows' %}<div><label>WinRM-Verfahren</label><select name="transport">{% for x in ['ntlm','kerberos','credssp','basic'] %}<option {{ 'selected' if pr.transport==x }}>{{x}}</option>{% endfor %}</select></div>{% endif %}
 <div id="pwbox"><label>{{ 'Windows-Passwort' if pr.type=='windows' else 'SSH-Passwort' }}</label><input name="password" type="password" autocomplete="new-password" placeholder="{{ 'gespeichert – leer lassen zum Behalten' if pr.password else '' }}"></div>
</div>{% if pr.password %}<label><input type="checkbox" name="clear_password" value="1" style="width:auto"> gespeichertes Anmelde-Passwort entfernen</label>{% endif %}
{% if pr.type=='linux' %}<h2>Rechte erhöhen (für Playbooks mit <code>become: true</code>)</h2><div class="grid">
 <div><label>Verfahren</label><select name="become" id="become" onchange="tg()">
  <option value="none" {{ 'selected' if pr.become=='none' }}>keines</option>
  <option value="sudo" {{ 'selected' if pr.become=='sudo' }}>sudo (eigenes Passwort)</option>
  <option value="su" {{ 'selected' if pr.become=='su' }}>su (Passwort des Zielbenutzers)</option></select></div>
 <div class="bb"><label>Zielbenutzer</label><input name="become_user" value="{{ pr.become_user or 'root' }}"></div>
 <div class="bb"><label id="bpl">Passwort für sudo / su</label><input name="become_password" type="password" autocomplete="new-password" placeholder="{{ 'gespeichert – leer lassen zum Behalten' if pr.become_password else 'leer bei sudo ohne Passwort (NOPASSWD)' }}"></div>
</div>{% if pr.become_password %}<label class="bb"><input type="checkbox" name="clear_become_password" value="1" style="width:auto"> gespeichertes sudo/su-Passwort entfernen</label>{% endif %}{% endif %}
<p><button class="acc">Speichern</button> <a class="btn" href="/einstellungen">Abbrechen</a></p></form>
{% if pid %}<form method="post" onsubmit="return confirm('Profil löschen?')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="delete" value="1"><button class="danger">Profil löschen</button></form>{% endif %}</div>
<script>function tg(){var a=document.getElementById('auth'),b=document.getElementById('become');
if(a)document.getElementById('pwbox').style.display=a.value=='password'?'':'none';
if(b){document.querySelectorAll('.bb').forEach(function(e){e.style.visibility=b.value=='none'?'hidden':''});
document.getElementById('bpl').textContent=b.value=='su'?'Passwort des Zielbenutzers (für su)':'sudo-Passwort des Anmeldebenutzers';}}tg();</script>
{% endblock %}"""


USERS = """{% extends "base.html" %}{% block title %}Benutzer{% endblock %}{% block body %}<div class="fit">
<h1>Benutzer <span class="mut small">({{ users|length }})</span></h1>
<div class="bar"><a class="btn acc" href="/benutzer/neu">+ Benutzer</a><a class="btn" href="/benutzer/ad">+ AD-Benutzer</a><a class="btn" href="/benutzer/gruppen">&#128101; Benutzergruppen</a><span style="flex:1"></span><a class="btn" href="/benutzer/verzeichnis">&#9881; E-Mail &amp; AD</a></div>
<p class="mut small">Der Admin <b>{{ session.user }}</b> sieht und darf alles. Benutzer sehen nur die freigegebenen Standorte bzw. Maschinen.</p>
<table class="auto"><tr><th>Benutzer</th><th>Anmeldung</th><th>Darf</th><th>Sieht</th><th>Geändert</th><th></th></tr>
{% for u in users %}<tr><td><b>{{ u.display or u.name }}</b>{% if u.display %}<div class="mut small">{{ u.name }}</div>{% endif %}{% if u.email %}<div class="mut small">{{ u.email }}</div>{% endif %}</td>
<td class="small">{% if u.source == 'ad' %}<span class="tag windows">AD</span>{% else %}<span class="tag">lokal</span>{% endif %}
 {% if u.invite and u.invite.expires > now_ts %}<div class="st-warn">Einladung offen</div>{% elif u.source != 'ad' and not u.hash %}<div class="st-err">kein Passwort</div>{% elif u.must_change %}<div class="st-warn">muss Passwort ändern</div>{% endif %}</td>
<td class="small">{% set ea = eff_actions(u) %}{% if ea %}<span class="st-ok">{{ ea|map('extract', actions)|join(', ') }}</span>{% else %}<span class="mut">nur ansehen</span>{% endif %}
 {% if u.groups %}<div class="mut">Gruppen: {{ u.groups|map('extract', gname)|join(', ') }}</div>{% endif %}</td>
<td class="small">{% for x in summary(u) %}<div>&#128205; {{ x }}</div>{% else %}{% if u.groups %}<span class="mut">über Gruppen</span>{% else %}<span class="st-err">nichts freigegeben</span>{% endif %}{% endfor %}</td>
<td class="small mut" style="white-space:nowrap">{{ (u.changed or u.created or '')|de_date }}</td>
<td><a class="btn" href="/benutzer/{{ u.name }}">Bearbeiten</a></td></tr>
{% else %}<tr><td colspan="6" class="mut">Noch keine Benutzer.</td></tr>{% endfor %}</table></div>{% endblock %}"""

USER = """{% extends "base.html" %}{% block title %}{{ uname or 'Neuer Benutzer' }}{% endblock %}{% block body %}<div class="fit" style="min-width:min(780px,100%)">
<h1>{{ (u.display or uname) if uname else 'Neuer Benutzer' }} {% if u.source == 'ad' %}<span class="tag windows">AD</span>{% elif uname %}<span class="tag">lokal</span>{% endif %}</h1>
<form method="post" id="uf"><input type="hidden" name="csrf" value="{{csrf}}">
<div class="card"><h2 style="margin-top:0">Anmeldung</h2><div class="grid">
 <div><label>Benutzername</label><input name="name" value="{{ u.name }}" {{ 'disabled' if uname else 'required autofocus' }} pattern="[A-Za-z0-9][A-Za-z0-9._@\\-]{1,40}"></div>
 <div><label>E-Mail{{ ' (aus dem AD)' if u.source == 'ad' }}</label><input name="email" type="email" value="{{ u.email or '' }}" placeholder="fuer Einladung / Passwort-Link"></div>
</div>
{% if u.source == 'ad' %}<p class="small mut">Meldet sich mit dem Domänen-Passwort an (geprüft per LDAP). {{ u.ad_dn or '' }}</p>
{% else %}<div class="grid">
 <div><label>{{ 'Neues Passwort (leer = unverändert)' if uname else 'Passwort' }}</label><input name="password" id="pw1" type="password" autocomplete="new-password" minlength="10"></div>
 <div><label>Passwort wiederholen</label><input name="password2" id="pw2" type="password" autocomplete="new-password"></div>
 <div><button type="button" onclick="genPw()">&#127922; Passwort erzeugen</button></div>
</div><div class="hint">mindestens 10 Zeichen · ein erzeugtes Passwort wird angezeigt, damit du es weitergeben kannst</div>
<label class="plain" style="display:block;margin-top:6px"><input type="checkbox" name="must_change" value="1" {{ 'checked' if not uname }}> beim ersten Login ändern lassen</label>
{% if not uname %}<label class="plain" style="display:block;margin-top:6px"><input type="checkbox" name="send_invite" value="1" {{ '' if mail_ok else 'disabled' }} onchange="document.getElementById('pw1').required=false"> stattdessen per E-Mail einladen – der Benutzer legt sein Passwort selbst fest{% if not mail_ok %} <span class="mut small">(erst <a href="/benutzer/verzeichnis">E-Mail einrichten</a>)</span>{% endif %}</label>{% endif %}
{% endif %}
</div>
<div class="card"><h2 style="margin-top:0">Gruppen</h2>{% for g in all_groups %}
<label class="plain" style="display:block"><input type="checkbox" name="grp" value="{{ g.id }}" {{ 'checked' if g.id in (u.groups or []) }}> <b>{{ g.name }}</b> <span class="mut small">{{ g.actions|map('extract', actions)|join(', ') or 'nur ansehen' }}</span></label>
{% else %}<span class="mut small">Noch keine Gruppen – <a href="/benutzer/gruppen">Benutzergruppe anlegen</a>.</span>{% endfor %}</div>
<div class="card"><h2 style="margin-top:0">Was darf {{ uname or 'der Benutzer' }}?</h2>{% set acts = own_actions(u) %}{% set inherited = eff_actions(u) %}{% include "acts.html" %}</div>
{% set pobj = u.perms %}{% set ptitle = 'Was darf ' ~ (uname or 'der Benutzer') ~ ' selbst sehen?' %}{% set phint = 'zusätzlich zu dem, was seine Gruppen freigeben' if all_groups else '' %}{% include "perms.html" %}
<p><button class="acc">Speichern</button> <a class="btn" href="/benutzer">Zurück</a></p></form>
{% if uname %}<div class="card"><h2 style="margin-top:0">{{ 'Zugang' if u.source == 'ad' else 'Passwort zurücksetzen / einladen' }}</h2><div class="bar" style="margin:0">
{% if u.source != 'ad' %}<form class="inl" method="post" onsubmit="return confirm('Neues Zufallspasswort für {{ uname }} erzeugen? Das alte gilt dann nicht mehr.')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="act" value="resetpw"><button>&#127922; Zufallspasswort setzen</button></form>{% endif %}
<form class="inl" method="post"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="act" value="{{ 'invite' if u.source == 'ad' else 'resetmail' }}"><button {{ '' if (mail_ok and u.email) else 'disabled' }}>&#9993; {{ 'Zugangsinfo per E-Mail' if u.source == 'ad' else 'Link zum Passwort-Festlegen per E-Mail' }}</button></form>
</div><div class="hint">{% if not mail_ok %}E-Mail noch nicht eingerichtet – <a href="/benutzer/verzeichnis">E-Mail &amp; AD</a>{% elif not u.email %}keine E-Mail-Adresse eingetragen{% elif u.source != 'ad' %}Der Link gilt 72 Stunden; das Zufallspasswort wird einmal angezeigt und muss beim nächsten Login geändert werden.{% endif %}</div></div>
<form method="post" onsubmit="return confirm('Benutzer {{ uname }} wirklich löschen?')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="act" value="delete"><button class="danger">Benutzer löschen</button></form>{% endif %}
</div>
<script>
function tick(a,g){a.closest('.hl').querySelectorAll('input[type=checkbox]').forEach(function(c){c.checked = g==='*' || (g!=='' && c.dataset.g===g)});return false}
function genPw(){var al='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#%+-=?',pw='',r=new Uint32Array(16);
 do{crypto.getRandomValues(r);pw='';for(var i=0;i<16;i++)pw+=al[r[i]%al.length]}while(!(/[A-Z]/.test(pw)&&/[a-z]/.test(pw)&&/[0-9]/.test(pw)&&/[!#%+\\-=?]/.test(pw)));
 ['pw1','pw2'].forEach(function(id){var e=document.getElementById(id);e.value=pw;e.type='text'})}
</script>{% endblock %}"""

DIRECTORY = """{% extends "base.html" %}{% block title %}E-Mail & AD{% endblock %}{% block body %}<div class="fit" style="min-width:min(780px,100%)">
<h1>E-Mail &amp; Active Directory</h1>
<form method="post" class="card" id="mail"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="mail">
<h2 style="margin-top:0">E-Mail-Versand (Einladungen, Passwort-Links)</h2><div class="grid">
 <div><label>SMTP-Server</label><input name="host" value="{{ mail.host }}" placeholder="mail.example.com"></div>
 <div><label>Verschlüsselung</label><select name="security">{% for k, v in [('starttls','STARTTLS (587)'),('ssl','SSL/TLS (465)'),('none','keine')] %}<option value="{{k}}" {{ 'selected' if mail.security==k }}>{{v}}</option>{% endfor %}</select></div>
 <div><label>Port</label><input name="port" type="number" value="{{ mail.port }}"></div>
 <div><label>Benutzer (leer = ohne Anmeldung)</label><input name="user" value="{{ mail.user }}" autocomplete="off"></div>
 <div><label>Passwort {{ '(gespeichert – leer = unverändert)' if mail.password }}</label><input name="password" type="password" autocomplete="new-password"></div>
 <div><label>Absender</label><input name="sender" value="{{ mail.sender }}" placeholder="Ansible-UI &lt;ansible@example.com&gt;"></div>
 <div><label>Adresse der Ansible-UI (für Links)</label><input name="base_url" value="{{ mail.base_url }}" placeholder="https://ansible.example.com"></div>
 <div><label>Test-E-Mail an (optional)</label><input name="test_to" type="email" placeholder="du@example.com"></div>
</div>{% if mail.password %}<label class="plain" style="display:block;margin-top:6px"><input type="checkbox" name="clear_password" value="1"> gespeichertes Passwort löschen</label>{% endif %}
<p><button class="acc">Speichern</button> <span class="mut small">mit Test-Adresse wird gleich eine Test-E-Mail geschickt</span></p></form>
<form method="post" class="card" id="ad"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="form" value="ad">
<h2 style="margin-top:0">Active Directory (Anmeldung mit Domänen-Konto)</h2>
<label class="plain" style="display:block;margin-bottom:6px"><input type="checkbox" name="enabled" value="1" {{ 'checked' if ad.enabled }}> AD-Anmeldung aktiv</label><div class="grid">
 <div><label>Domänencontroller (mehrere mit Komma)</label><input name="servers" value="{{ ad.servers }}" placeholder="dc1.example.local, dc2.example.local"></div>
 <div><label>Verbindung</label><select name="security">{% for k, v in [('starttls','LDAP + StartTLS (389)'),('ldaps','LDAPS (636)'),('none','LDAP unverschlüsselt (389)')] %}<option value="{{k}}" {{ 'selected' if ad.security==k }}>{{v}}</option>{% endfor %}</select></div>
 <div><label>Port</label><input name="port" type="number" value="{{ ad.port }}"></div>
 <div><label>Basis-DN</label><input name="base_dn" value="{{ ad.base_dn }}" placeholder="DC=example,DC=local"></div>
 <div><label>Dienstkonto (zum Suchen)</label><input name="bind_user" value="{{ ad.bind_user }}" placeholder="svc-ansible@example.local" autocomplete="off"></div>
 <div><label>Passwort Dienstkonto {{ '(gespeichert – leer = unverändert)' if ad.bind_password }}</label><input name="bind_password" type="password" autocomplete="new-password"></div>
 <div><label>Zusätzlicher Filter (optional)</label><input name="user_filter" value="{{ ad.user_filter }}" placeholder="memberOf=CN=Ansible-Benutzer,OU=Gruppen,DC=example,DC=local"></div>
 <div><label>Domäne (Anzeige, optional)</label><input name="domain" value="{{ ad.domain }}" placeholder="EXAMPLE"></div>
</div><label class="plain" style="display:block;margin-top:6px"><input type="checkbox" name="verify" value="1" {{ 'checked' if ad.verify }}> Zertifikat des DCs prüfen (nur mit vertrauenswürdigem Zertifikat)</label>
<div class="hint">Unverschlüsselt würde das Passwort im Klartext übers Netz gehen – besser StartTLS oder LDAPS.</div>
<p><button class="acc">Speichern</button> <button name="test" value="1">Speichern + Verbindung testen</button></p></form>
<p><a class="btn" href="/benutzer">Zurück zu den Benutzern</a></p></div>{% endblock %}"""

AD_ADD = """{% extends "base.html" %}{% block title %}AD-Benutzer hinzufügen{% endblock %}{% block body %}<div class="fit" style="min-width:min(780px,100%)">
<h1>AD-Benutzer hinzufügen</h1>
{% if not conf.enabled %}<div class="flash err">AD ist noch nicht eingerichtet bzw. nicht aktiv – <a href="/benutzer/verzeichnis#ad">E-Mail &amp; AD</a>.</div>{% endif %}
<form method="get" class="bar"><input name="q" value="{{ q }}" placeholder="Name, Anmeldename oder E-Mail" style="width:320px" autofocus><button class="acc">Suchen</button></form>
{% if err %}<div class="flash err">{{ err }}</div>{% endif %}
{% if res %}<table class="auto"><tr><th>Name</th><th>Anmeldename</th><th>E-Mail</th><th></th></tr>
{% for e in res %}<tr class="{{ 'off' if e.disabled }}"><td>{{ e.display or '–' }}{% if e.disabled %} <span class="mut small">(deaktiviert)</span>{% endif %}</td><td>{{ e.sam }}</td><td class="small">{{ e.mail or '–' }}</td>
<td>{% if e.sam|lower in have %}<span class="mut small">schon vorhanden</span>{% elif not e.disabled %}<form method="post" class="inl"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="sam" value="{{ e.sam }}"><button>Hinzufügen</button></form>{% endif %}</td></tr>{% endfor %}</table>
{% if res|length >= 50 %}<p class="mut small">Nur die ersten 50 Treffer – Suche genauer eingrenzen.</p>{% endif %}
{% elif q is defined and request.args.get('q') is not none and not err %}<p class="mut">Keine Treffer.</p>{% endif %}
<p><a class="btn" href="/benutzer">Zurück</a></p></div>{% endblock %}"""

INVITE = """{% extends "base.html" %}{% block title %}Passwort festlegen{% endblock %}{% block body %}
<div class="card" style="max-width:420px;margin:60px auto"><h1>Ansible-UI</h1>{% if not u %}<p class="st-err">Dieser Link ist ungültig oder abgelaufen.</p><p class="mut">Bitte beim Admin einen neuen anfordern.</p><p><a class="btn" href="/login">Zur Anmeldung</a></p>
{% else %}<p>Passwort festlegen für <b>{{ u.name }}</b></p><form method="post">
<label>Neues Passwort (mind. 10 Zeichen)</label><input name="new_password" type="password" autocomplete="new-password" minlength="10" required autofocus>
<label>Wiederholen</label><input name="new_password2" type="password" autocomplete="new-password" required>
<p><button class="acc">Speichern</button></p></form>{% endif %}</div>{% endblock %}"""

PASSWORD = """{% extends "base.html" %}{% block title %}Passwort{% endblock %}{% block body %}
<div class="card" style="max-width:420px;margin:30px auto"><h1>Passwort ändern</h1><form method="post"><input type="hidden" name="csrf" value="{{csrf}}">
<label>Aktuelles Passwort</label><input name="old_password" type="password" autocomplete="current-password" required>
<label>Neues Passwort (mind. 10 Zeichen)</label><input name="new_password" type="password" autocomplete="new-password" minlength="10" required>
<label>Neues Passwort wiederholen</label><input name="new_password2" type="password" autocomplete="new-password" required>
<p><button class="acc">Ändern</button></p></form></div>{% endblock %}"""

FORBIDDEN = """{% extends "base.html" %}{% block title %}Keine Berechtigung{% endblock %}{% block body %}
<div class="card" style="max-width:480px;margin:40px auto"><h1>Keine Berechtigung</h1><p class="mut">Dafür fehlen dir die Rechte. Wende dich an den Admin.</p>
<p><a class="btn acc" href="/">Zur Maschinenliste</a></p></div>{% endblock %}"""

PERMS = """<div class="card"><h2 style="margin-top:0">{{ ptitle }}</h2>{% if phint %}<div class="hint" style="margin-bottom:8px">{{ phint }}</div>{% endif %}
<table class="dlg">{% for loc in locs %}{% set i = loop.index0 %}{% set v = pobj.get(loc) %}{% set mode = 'all' if v == '*' else ('linux' if v == 'group:linux' else ('windows' if v == 'group:windows' else ('sel' if v else ''))) %}
{% set lh = hs|selectattr('location', 'equalto', loc)|list if loc else hs|rejectattr('location')|list %}
<tr><td style="width:28%"><b>&#128205; {{ loc or 'ohne Standort' }}</b><div class="mut small">{{ lh|length }} Maschine(n): {{ lh|selectattr('group', 'equalto', 'linux')|list|length }} Linux · {{ lh|selectattr('group', 'equalto', 'windows')|list|length }} Windows</div></td>
<td><select name="m{{i}}" style="width:auto" onchange="this.closest('td').querySelector('.hl').hidden = this.value != 'sel'">
 <option value="" {{ 'selected' if not mode }}>nichts</option><option value="all" {{ 'selected' if mode == 'all' }}>alle Maschinen</option>
 <option value="linux" {{ 'selected' if mode == 'linux' }}>alle Linux-Maschinen</option><option value="windows" {{ 'selected' if mode == 'windows' }}>alle Windows-Maschinen</option>
 <option value="sel" {{ 'selected' if mode == 'sel' }}>nur ausgewählte</option></select>
 <span class="mut small">„alle …“ gilt auch für künftige Maschinen</span>
 <div class="hl" {{ '' if mode == 'sel' else 'hidden' }} style="margin-top:6px"><div class="small" style="margin-bottom:4px">Anhaken: <a href="#" onclick="return tick(this,'linux')">alle Linux</a> · <a href="#" onclick="return tick(this,'windows')">alle Windows</a> · <a href="#" onclick="return tick(this,'*')">alle</a> · <a href="#" onclick="return tick(this,'')">keine</a></div>
 {% for g in groups %}{% set gh = lh|selectattr('group', 'equalto', g)|list %}{% if gh %}<div class="mut small" style="margin-top:4px;text-transform:uppercase">{{ g }}</div>{% for h in gh %}
 <label class="plain" style="display:block"><input type="checkbox" name="h{{i}}" value="{{ h.name }}" data-g="{{ h.group }}" {{ 'checked' if v and v is not string and h.name in v }}> {{ h.display or h.name }} <span class="tag {{ h.group }}">{{ h.group }}</span>{% if not h.enabled %} <span class="mut small">inaktiv</span>{% endif %}</label>
 {% endfor %}{% endif %}{% endfor %}{% if not lh %}<span class="mut small">keine Maschinen</span>{% endif %}</div></td></tr>
{% else %}<tr><td class="mut">Noch keine Standorte – unter Einstellungen anlegen.</td></tr>{% endfor %}</table></div>"""

ACTS = """<div class="grid top" style="grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:4px 12px">{% for k, v in actions.items() %}
<label class="plain" style="display:block"><input type="checkbox" name="a_{{ k }}" value="1" {{ 'checked' if k in acts }}> {{ v }}{% if k in inherited and k not in acts %} <span class="mut small">(über Gruppe)</span>{% endif %}</label>{% endfor %}</div>
<div class="hint">ohne Haken nur ansehen. „Planen“ braucht zusätzlich „Updates installieren“ bzw. „Neustart“. Maschinen, Playbooks, Einstellungen, Upgrades und Benutzer bleiben immer beim Admin.</div>"""

GROUPS_T = """{% extends "base.html" %}{% block title %}Benutzergruppen{% endblock %}{% block body %}<div class="fit">
<h1>Benutzergruppen <span class="mut small">({{ grps|length }})</span></h1>
<p class="mut small">Eine Gruppe bündelt Rechte und sichtbare Standorte/Maschinen. Ein Benutzer darf alles, was seine Gruppen und seine eigenen Einstellungen zusammen erlauben.</p>
<table class="auto"><tr><th>Gruppe</th><th>Darf</th><th>Sieht</th><th>Mitglieder</th><th></th></tr>
{% for g in grps %}<tr><td><b>{{ g.name }}</b></td><td class="small">{{ g.actions|map('extract', actions)|join(', ') or 'nur ansehen' }}</td>
<td class="small">{% for x in summary(g) %}<div>&#128205; {{ x }}</div>{% else %}<span class="mut">nichts</span>{% endfor %}</td>
<td class="small">{{ members[g.id]|join(', ') or '–' }}</td><td><a class="btn" href="/benutzer/gruppe/{{ g.id }}">Bearbeiten</a></td></tr>
{% else %}<tr><td colspan="5" class="mut">Noch keine Gruppen.</td></tr>{% endfor %}</table>
<p><a class="btn acc" href="/benutzer/gruppe/neu">+ Gruppe</a> <a class="btn" href="/benutzer">Zu den Benutzern</a></p></div>{% endblock %}"""

GROUP_T = """{% extends "base.html" %}{% block title %}{{ g.name or 'Neue Gruppe' }}{% endblock %}{% block body %}<div class="fit" style="min-width:min(780px,100%)">
<h1>{{ g.name or 'Neue Gruppe' }}</h1><form method="post"><input type="hidden" name="csrf" value="{{csrf}}">
<div class="card"><label>Name der Gruppe</label><input name="name" value="{{ g.name }}" required placeholder="z. B. Techniker Büro" style="max-width:360px"></div>
<div class="card"><h2 style="margin-top:0">Was darf die Gruppe?</h2>{% set acts = g.actions %}{% set inherited = [] %}{% include "acts.html" %}</div>
{% set pobj = g.perms %}{% set ptitle = 'Was sieht die Gruppe?' %}{% set phint = '' %}{% include "perms.html" %}
<div class="card"><h2 style="margin-top:0">Mitglieder</h2>{% for u in us %}
<label class="plain" style="display:block"><input type="checkbox" name="member" value="{{ u.name }}" {{ 'checked' if u.name in members }}> {{ u.display or u.name }}{% if u.source == 'ad' %} <span class="tag windows">AD</span>{% endif %}</label>
{% else %}<span class="mut small">Noch keine Benutzer.</span>{% endfor %}</div>
<p><button class="acc">Speichern</button> <a class="btn" href="/benutzer/gruppen">Zurück</a></p></form>
{% if gid %}<form method="post" onsubmit="return confirm('Gruppe {{ g.name }} löschen? Die Mitglieder verlieren die Rechte dieser Gruppe.')"><input type="hidden" name="csrf" value="{{csrf}}"><input type="hidden" name="act" value="delete"><button class="danger">Gruppe löschen</button></form>{% endif %}
</div><script>function tick(a,g){a.closest('.hl').querySelectorAll('input[type=checkbox]').forEach(function(c){c.checked = g==='*' || (g!=='' && c.dataset.g===g)});return false}</script>{% endblock %}"""

def de_date(v):
    """ISO-Datum/Zeitstempel ("2026-11-18" / "2026-11-18 04:00:12") -> deutsch "18.11.2026" / "18.11.2026 04:00"."""
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{2}:\d{2}))?", str(v or ""))
    return f"{m[3]}.{m[2]}.{m[1]}" + (f" {m[4]}" if m[4] else "") if m else (v or "")


app.jinja_env.filters["de_date"] = de_date
app.jinja_env.filters["extract"] = lambda key, container: container.get(key, key) if hasattr(container, "get") else key
app.jinja_loader = DictLoader({"perms.html": PERMS, "acts.html": ACTS, "groups.html": GROUPS_T, "group.html": GROUP_T, "directory.html": DIRECTORY, "ad_add.html": AD_ADD, "invite.html": INVITE, "users.html": USERS, "user.html": USER, "password.html": PASSWORD, "forbidden.html": FORBIDDEN, "base.html": BASE, "login.html": LOGIN, "index.html": INDEX, "machine.html": MACHINE,
                               "playbooks.html": PLAYBOOKS, "runs.html": RUNS, "run.html": RUN, "settings.html": SETTINGS,
                               "profile.html": PROFILE})

os.makedirs(p("runs"), exist_ok=True)
os.makedirs(p("facts"), exist_ok=True)
SERVER = "gunicorn" in os.path.basename(sys.argv[0] if sys.argv else "")
if SERVER:
    # Beim Start des Webservers: Laeufe, die beim letzten Beenden noch liefen, als abgebrochen markieren
    # (nicht bei "import app" aus Hilfsskripten - das hat laufende Laeufe faelschlich abgebrochen gemeldet)
    with LOCK:
        _r = load("runs/index.json", [])
        for _x in _r:
            if _x["status"] == "laeuft":
                _x["status"], _x["end"] = "abgebrochen", now()
        save("runs/index.json", _r)

# naechtliche Update-Pruefung nur im Webserver-Prozess starten (nicht bei "import app" in Hilfsskripten)
if SERVER:
    threading.Thread(target=nightly_loop, daemon=True).start()
    threading.Thread(target=schedule_loop, daemon=True).start()
