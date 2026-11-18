#!/bin/sh
set -e
mkdir -p /data/ssh /data/facts /data/playbooks /data/runs
chmod 700 /data/ssh
if [ ! -f /data/ssh/id_ed25519 ]; then
  ssh-keygen -q -t ed25519 -N "" -C "ansible-ui" -f /data/ssh/id_ed25519
fi
chmod 600 /data/ssh/id_ed25519
if [ ! -f /data/playbooks/updates-installieren-linux.yml ]; then
  cat > /data/playbooks/updates-installieren-linux.yml <<'EOF'
# Updates installieren - EIN Playbook fuer alle Linux-Systeme:
#   Debian / Ubuntu / Raspberry Pi OS (apt), Fedora / RHEL / Rocky / Alma (dnf/yum), openSUSE / SLES (zypper)
# Mit "Probelauf (--check)" wird nur angezeigt, was passieren wuerde.
# Neustart: nur wenn unten neustart_erlaubt auf true steht UND das System einen Neustart verlangt.
- hosts: linux
  gather_facts: true
  become: true
  vars:
    neustart_erlaubt: false
  tasks:
    - name: Updates installieren (apt)
      environment:
        DEBIAN_FRONTEND: noninteractive
        APT_LISTCHANGES_FRONTEND: none
      ansible.builtin.apt:
        update_cache: true
        upgrade: dist
        autoremove: true
      when: ansible_facts["pkg_mgr"] == "apt"
    - name: Updates installieren (dnf/yum)
      ansible.builtin.dnf:
        name: "*"
        state: latest
      when: ansible_facts["pkg_mgr"] in ["dnf", "dnf5", "yum"]
    - name: Updates installieren (zypper)
      community.general.zypper:
        name: "*"
        state: latest
      when: ansible_facts["pkg_mgr"] == "zypper"
    - name: Neustart noetig? (Debian/Ubuntu)
      ansible.builtin.stat:
        path: /var/run/reboot-required
      register: reboot_file
    - name: Neustart noetig? (dnf/yum)
      ansible.builtin.command: needs-restarting -r
      register: reboot_rpm
      failed_when: false
      changed_when: false
      when: ansible_facts["pkg_mgr"] in ["dnf", "dnf5", "yum"]
    - name: Ergebnis
      ansible.builtin.debug:
        msg: "Neustart noetig: {{ reboot_file.stat.exists or (reboot_rpm.rc | default(0)) == 1 }}"
    - name: Neustart (nur wenn erlaubt)
      ansible.builtin.reboot:
        reboot_timeout: 900
      when: neustart_erlaubt | bool and (reboot_file.stat.exists or (reboot_rpm.rc | default(0)) == 1)
EOF
fi
if [ ! -f /data/playbooks/updates-installieren-windows.yml ]; then
  cat > /data/playbooks/updates-installieren-windows.yml <<'EOF'
# Updates installieren - EIN Playbook fuer Windows 10, Windows 11 und Windows Server
# (alle nutzen dieselbe Windows-Update-Schnittstelle).
# Mit "Probelauf (--check)" wird nur gesucht, nichts installiert.
# Neustart: nur wenn unten neustart_erlaubt auf true steht - sonst bleibt "Neustart noetig" stehen.
- hosts: windows
  gather_facts: false
  vars:
    neustart_erlaubt: false
  tasks:
    - name: Windows-Updates installieren
      ansible.windows.win_updates:
        category_names: [SecurityUpdates, CriticalUpdates, UpdateRollups, Updates]
        state: installed
        reboot: "{{ neustart_erlaubt | bool }}"
        reboot_timeout: 1800
      register: wu
    - name: Ergebnis
      ansible.builtin.debug:
        msg: >-
          {% if ansible_check_mode %}PROBELAUF - wuerde installieren: {{ wu.found_update_count | default(0) }} Update(s)
          {% else %}{{ wu.installed_update_count | default(0) }} installiert, {{ wu.failed_update_count | default(0) }} fehlgeschlagen,
          Neustart noetig: {{ 'ja' if wu.reboot_required | default(false) else 'nein' }}{% endif %}
          {{ (wu.updates | default({})).values() | map(attribute='title') | list }}
EOF
fi
exec gunicorn --workers 1 --threads 8 --timeout 0 --bind 0.0.0.0:3000 app:app
