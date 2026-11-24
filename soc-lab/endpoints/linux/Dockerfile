# Ubuntu endpoint with SSH (attack target) and the Wazuh agent
FROM ubuntu:24.04
ARG WAZUH_VERSION=4.14.10-1
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y curl gnupg lsb-release openssh-server rsyslog sudo \
 && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update && WAZUH_MANAGER=wazuh.manager WAZUH_AGENT_NAME=linux-endpoint-01 apt-get install -y wazuh-agent=${WAZUH_VERSION} \
 && mkdir -p /run/sshd && rm -rf /var/lib/apt/lists/*
# Lab user with a deliberately weak password, used for brute-force exercises
RUN useradd -m -s /bin/bash labuser && echo 'labuser:Summer2026!' | chpasswd
COPY auth-log.xml /tmp/auth-log.xml
RUN cat /tmp/auth-log.xml >> /var/ossec/etc/ossec.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
