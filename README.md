# Cybersecurity Lab

Hands-on security projects by **David Alabi**: detection engineering, endpoint security, and incident response.

| Project | Status | What it shows |
|---|---|---|
| [Home SOC Lab: Wazuh SIEM + Detection Engineering](soc-lab/) | 🟢 Active | SIEM deployment, Sysmon telemetry, adversary simulation (Atomic Red Team), custom ATT&CK-mapped detections, incident reports |
| Active Directory Attack & Defense (Azure) | ⏳ Planned | Domain controller, AD attacks (Kerberoasting, password spraying), detection and hardening |
| macOS / Jamf Security Hardening | ⏳ Planned | CIS macOS benchmark, compliance scripting, macOS threat detection |

**Latest write-up:** [IR-001: Scheduled Task Persistence](soc-lab/incident-reports/IR-001-scheduled-task-persistence.md).
Found that Wazuh's built-in rules rated scheduled-task persistence as level 3 with the wrong ATT&CK mapping, then wrote
and validated a level-10 custom detection for T1053.005.

> All attack simulations run in an isolated personal lab against machines I own.
