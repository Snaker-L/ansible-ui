# Ansible-UI

Kleine deutschsprachige Weboberfläche für [Ansible](https://www.ansible.com/) mit Maschinenliste –
gedacht für Heimnetz und kleine Umgebungen mit Linux- und Windows-Rechnern.

## Funktionen

- Maschinenliste mit Standorten, Gruppen (Linux/Windows), Status-, Update- und Standortfiltern
- Mehrere Adressen pro Maschine (z. B. LAN und WLAN) – die erste erreichbare wird verwendet
- Zugangsprofile (SSH-Schlüssel oder Passwort, `sudo`/`su`, WinRM für Windows)
- **Ping** und **Info Device** (Ansible-Fakten: Betriebssystem, CPU, RAM, Laufzeit, IPs)
- Update-Prüfung (apt, dnf/yum, zypper, Windows Update), optional jede Nacht automatisch
- Updates installieren: einzeln, für alle bzw. eine Auswahl – im Dialog abwählbar, sofort oder **geplant**
  (Datum/Uhrzeit)
- Neustart: einzeln oder im Dialog in Stufen – gleiche Nummer = gleichzeitig, die nächste Stufe erst, wenn alle der
  vorigen vollständig laufen (sonst Abbruch); optional Pause zwischen den Stufen, sofort oder geplant
- Distributions-Upgrade (Debian/Ubuntu)
- Playbook-Editor und Läufe mit vollständigem Log
- Benutzer und Benutzergruppen: der Admin gibt Standorte frei – ganz oder nur ausgewählte Maschinen – und legt die
  Rechte einzeln fest (Ping, Info Device, Updates prüfen, Updates installieren, Planen, Neustart); ein Benutzer darf
  alles, was seine Gruppen und seine eigenen Einstellungen zusammen erlauben. Maschinen, Playbooks, Einstellungen und
  Upgrades bleiben beim Admin. Rechte pro Standort auch als „alle Linux“ / „alle Windows“
- Benutzer per E-Mail einladen (Link zum Passwort-Festlegen, 72 h), Passwort erzeugen oder zurücksetzen
  (Benutzer muss es beim nächsten Login ändern)
- Active Directory: AD-Benutzer suchen und übernehmen, Anmeldung mit dem Domänen-Passwort (LDAPS oder StartTLS,
  mehrere DCs, optionaler Gruppenfilter)

## Starten

```sh
docker build -t ansible-ui:local .
docker run -d --name ansible-ui -p 3000:3000 \
  -e ADMIN_PASSWORD='bitte-aendern' \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -v ansible_ui_data:/data \
  ansible-ui:local
```

Danach `http://<host>:3000` öffnen und mit `admin` und dem Start-Passwort anmelden.
Das Passwort lässt sich unter *Einstellungen* ändern (wird nur als Hash gespeichert).

### Umgebungsvariablen

| Variable         | Bedeutung                                          | Standard |
|------------------|----------------------------------------------------|----------|
| `ADMIN_USER`     | Benutzername                                       | `admin`  |
| `ADMIN_PASSWORD` | Start-Passwort (gilt, bis es in der UI geändert wird) | –     |
| `SECRET_KEY`     | Schlüssel für Sitzungs-Cookies                      | zufällig bei jedem Start |
| `DATA_DIR`       | Datenverzeichnis                                   | `/data`  |

### Daten (`/data`)

`hosts.json` (Maschinen), `status.json`, `facts/`, `secrets.json` (Zugangsprofile, 0600),
`ssh/id_ed25519` (wird beim ersten Start erzeugt – öffentlicher Schlüssel unter *Einstellungen*),
`playbooks/`, `runs/`, `schedule.json` (geplante Update-Läufe), `users.json` (Benutzer, Passwörter nur als Hash, 0600), `groups.json` (Benutzergruppen), `directory.json` (SMTP und AD, 0600), `locations.json`, `settings.json`.

Den öffentlichen SSH-Schlüssel musst du selbst auf den Zielmaschinen hinterlegen.

## Hinweise

- Die Oberfläche ist für das interne Netz gedacht – nicht ungeschützt ins Internet stellen.
- Läuft die Ansible-UI selbst auf einem der verwalteten Docker-Hosts, diesen mit „Nicht bei Update alle“
  markieren: ein Docker-Update startet sonst den Container neu und bricht laufende Läufe ab.
