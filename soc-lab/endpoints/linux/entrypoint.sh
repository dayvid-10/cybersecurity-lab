#!/bin/bash
rsyslogd
/usr/sbin/sshd
/var/ossec/bin/wazuh-control start
tail -F /var/ossec/logs/ossec.log
