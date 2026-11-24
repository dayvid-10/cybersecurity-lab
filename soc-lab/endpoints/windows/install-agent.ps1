# Windows 11 lab endpoint setup: Sysmon + PowerShell logging + Wazuh agent
# Run in an ADMIN PowerShell on the Windows VM.
$ErrorActionPreference = 'Stop'
$Manager = '192.168.64.1'          # Mac host as seen from the UTM shared network
$AgentName = 'WIN11-ENDPOINT'
$WazuhVersion = '4.14.10-1'
$tmp = "$env:TEMP\labsetup"; New-Item -ItemType Directory -Force $tmp | Out-Null
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$ProgressPreference = 'SilentlyContinue'

Write-Host '[1/4] Installing Sysmon (ARM64) with SwiftOnSecurity config...'
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile "$tmp\Sysmon.zip"
Expand-Archive -Force "$tmp\Sysmon.zip" "$tmp\Sysmon"
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile "$tmp\sysmonconfig.xml"
& "$tmp\Sysmon\Sysmon64a.exe" -accepteula -i "$tmp\sysmonconfig.xml" | Out-Null

Write-Host '[2/4] Enabling PowerShell script block logging...'
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Force $k | Out-Null
Set-ItemProperty $k EnableScriptBlockLogging 1

Write-Host '[3/4] Installing Wazuh agent...'
Invoke-WebRequest "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi" -OutFile "$tmp\wazuh-agent.msi"
Start-Process msiexec.exe -Wait -ArgumentList "/i `"$tmp\wazuh-agent.msi`" /q WAZUH_MANAGER=$Manager WAZUH_AGENT_NAME=$AgentName"

Write-Host '[4/4] Forwarding Sysmon + PowerShell logs and starting agent...'
$conf = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
Add-Content $conf @'

<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
'@
Start-Service WazuhSvc
Get-Service *sysmon*, WazuhSvc | Format-Table Name, Status
Write-Host 'Done. Tell Claude to check the Wazuh dashboard.'
