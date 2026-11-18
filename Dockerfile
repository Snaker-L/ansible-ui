# Ansible-UI: Ansible + kleine deutsche Weboberflaeche mit Maschinenliste
# Bauen: docker build -t ansible-ui:local .
FROM python:3.13-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client sshpass tini ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# ansible 14.5.0 (Stand 2026-11-03, PyPI; bringt ansible-core 2.21.x mit); enthaelt ansible.windows / community.general
RUN pip install --no-cache-dir ansible==14.5.0 pywinrm flask gunicorn pyyaml ldap3==2.9.1

WORKDIR /app
COPY app.py seed.json entrypoint.sh /app/
RUN chmod 755 /app/entrypoint.sh

ENV PYTHONUNBUFFERED=1 \
    ANSIBLE_HOST_KEY_CHECKING=False \
    ANSIBLE_RETRY_FILES_ENABLED=False \
    ANSIBLE_FORCE_COLOR=0 \
    ANSIBLE_NOCOLOR=1 \
    ANSIBLE_TIMEOUT=30 \
    DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 3000
ENTRYPOINT ["tini", "--", "/app/entrypoint.sh"]
