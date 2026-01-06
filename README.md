# Threat Hunt Report: Credential Theft and Data Exfiltration Investigation

## Executive Summary

Azuki Import & Export Trading Co. experienced anomalous network activity and suspicious process executions between November 18-19, 2025. The activity originated from external RDP connections and escalated into a multi-stage attack involving credential theft, lateral movement, and data exfiltration. The investigation revealed behavior consistent with ADE SPIDER (APT-SL44), a financially motivated threat actor known for targeting logistics companies across East Asia. The attacker employed multiple techniques including defense evasion, persistence mechanisms, and anti-forensic measures to maintain access and extract sensitive data. This investigation reconstructs the complete attack timeline and documents the threat actor's tactics, techniques, and procedures.

## Background
- **Incident Date:** November 18-19, 2025  
- **Compromised Host:** azuki-logistics  
- **Threat Actor:** ADE SPIDER (APT-SL44, SilentLynx)  
- **Motivation:** Financial  
- **Target Profile:** Logistics and import/export companies, East Asia region  
- **Typical Dwell Time:** 21-45 days  
- **Attack Sophistication:** Moderate with preference for low-footprint techniques

---

## Investigation Steps

### 1. Initial Access: Remote Access Source & Compromised User Account

Searched for remote interactive sessions from external sources during the incident timeframe to identify the origin of unauthorized access. The analysis revealed that the external IP address 88.97.178.12 established an RDP connection to azuki-logistics, marking the initial access point for the attack. In addition, discovered that the account that was compromised and used for initial RDP access was the user account kenji.sato.

**Queries used to locate events:**

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-19))
| where DeviceName has "azuki"
| where LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| project TimeGenerated, RemoteIP, DeviceName, AccountName
| sort by TimeGenerated asc

```
<img width="1839" height="310" alt="POE_QR1" src="https://github.com/user-attachments/assets/2e07843b-250d-432d-a249-cf0cdfd2ba27" />

---

### 2. Discovery: Network Reconnaissance

Searched for evidence of network enumeration by focusing the search on arp commands since it's the most common command for enumerating network neighbors with hardware addresses. The command and argument used to enumerate network neighbours was arp -a. This command displays the Address Resolution Protocol (ARP) cache, showing IP addresses mapped to MAC (i.e., hardware) addresses of devices on the local network. It's also useful for revealing the local network topology for planning lateral movement.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-19))
| where FileName has "arp"
| where ProcessCommandLine has "-a"
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1840" height="263" alt="POE_QR3" src="https://github.com/user-attachments/assets/e670390f-ef41-42be-a5cb-702feb778b5a" />

---

### 3. Defense Evasion: Malware Staging Directory

Searched for the the primary staging directory where malware was stored and found that the primary staging directory C:\ProgramData\WindowsCache was created and hidden using attrib commands. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated  between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| where FileName in ("cmd.exe", "powershell.exe", "attrib.exe")
| where ProcessCommandLine has_any ("mkdir", "New-Item", "attrib", "md ")
| project TimeGenerated, FileName, ProcessCommandLine, DeviceName, AccountName
| sort by TimeGenerated asc

```
<img width="2535" height="256" alt="POE_QR4" src="https://github.com/user-attachments/assets/8dad5f3f-dc0c-4437-8f48-c80ce44cb8a7" />

---

### 4. Defense Evasion: File Extension Exclusions

Searched registry modifications to Windows Defender's exclusion settings to identify file extensions added by the attacker. Adding file extension exclusions prevents scanning of malicious files; thereby, revealing the scope of the defense evasion strategy. The attacker excluded .bat, .ps1, and .exe file extensions from Windows Defender scanning, allowing malicious scripts and executables to run undetected. A total of 3 file extensions were excluded.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey has "Windows Defender" and RegistryKey has "Exclusions"
| where RegistryKey has "Extensions"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated asc

```
<img width="2307" height="382" alt="POE_QR5" src="https://github.com/user-attachments/assets/51e2123d-1f1a-41bd-9fb4-6b51c4464dd5" />

---

### 5. Defense Evasion: Temporary Folder Exclusion 

Searched for folder path exclusions added to Windows Defender configuration to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected. The temporary folder C:\Users\KENJI~1.SAT\AppData\Local\Temp (i.e., kenji.sato's temp directory) was excluded from Defender scanning, allowing the attacker to freely download and execute malware.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey has "Windows Defender" and RegistryKey has "Exclusions" and RegistryKey has "Paths"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated asc

```
<img width="2655" height="331" alt="POE_QR6" src="https://github.com/user-attachments/assets/bbebc01b-4949-43ce-b016-4ceec7c1d2c0" />

---

### 6. Defense Evasion: Download Utility Abuse

Searched for the use of built-in Windows tools with network download capabilities that may have been used during the attack and discovered that certutil.exe, a legitimate Windows certificate utility, was used by the attacker to download malware from http://78.141.196.6:8080/. Also, note that the -urlcache -f flags enable file downloads while evading security controls.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato" or InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine has_any ("http://", "https://", ".exe", "download", "-o", "-outfile")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2395" height="335" alt="POE_QR7" src="https://github.com/user-attachments/assets/6bdbb5cb-55b9-4058-ac05-a0d3b03e5f0b" />

---

### 7. Persistence: Scheduled Task Name & Scheduled Task Target

Searched for the execution of scheduled task creation commands during the attack timeline since scheduled tasks provide reliable persistence across system reboots. In this case, the name of the scheduled task created for persistence was Windows Update Check. Note that the task name often attempts to blend in with legitimate Windows system maintenance. In addition, the task action was extracted from the scheduled task creation command line to reveal the exact persistence mechanism and malware location. The /tr parameter value indicates which executable runs at the scheduled time. The scheduled task was configured to execute C:\ProgramData\WindowsCache\svchost.exe, a malicious binary disguised as the legitimate Windows Host Process, ensuring automated re-execution after system reboots.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| project TimeGenerated, DeviceName, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2446" height="271" alt="POE_QR8" src="https://github.com/user-attachments/assets/385623e2-9556-4767-ab71-526db9d18644" />

---

### 8. Command & Control: C2 Server Address & C2 Communication Port

Searched for a command and control server since attackers typically utilize command and control infrastructure to remotely control compromised systems. A command and control server at 78.141.196.6 was contacted by malicious svchost.exe from multiple machines. In addition, command and control communications utilized port 443 (HTTPS) to blend in with legitimate encrypted web traffic, making network-based detection more difficult and allowing for the evasion of basic firewall rules.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where InitiatingProcessFolderPath has "WindowsCache" 
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl
| sort by TimeGenerated asc

```
<img width="2390" height="394" alt="POE_QR10B" src="https://github.com/user-attachments/assets/f8cd25f7-ac3c-4945-958f-e1dc6aa771a1" />

---

### 9. Credential Access: Credential Theft Tool

Searched for executables downloaded to the staging directory since credential dumping tools are typically used to extract authentication secrets from system memory and dicovered a credential dumping tool with the filename mm.exe.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "WindowsCache"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine

```
<img width="2649" height="809" alt="POE_QR12" src="https://github.com/user-attachments/assets/ec341bc9-d013-4018-a73d-124968bf3465" />

---

### 10. Credential Access: Memory Extraction Module 

Searched for command line arguments passed to the credential dumping tool to identify the specific module used to extract passwords from memory and discovered that the Mimikatz module "sekurlsa::logonpasswords" was used by the attacker to extract credentials from LSASS (Local Security Authority Subsystem Service) memory.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "mm.exe"
| project TimeGenerated, ProcessCommandLine

```
<img width="1948" height="330" alt="POE_QR13" src="https://github.com/user-attachments/assets/68801ab9-e4f7-4af6-b358-05a3104f9bed" />

---
### 11. Collection & Exfiltration: Data Staging Archive & Exfiltration Channel

Searched for evidence of ZIP file creation in the staging directory during the collection phase since attackers compress stolen data for efficient exfiltration. The compressed archive export-data.zip was created in the staging directory and prepared for exfiltration via the curl upload command. In addition, the attacker utilized Discord's webhook API to exfiltrate the compressed archive. Discord is a legitimate communication platform commonly allowed through firewalls, making this exfiltration technique effective for bypassing network security controls.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "WindowsCache" and ProcessCommandLine has ".zip"
| project TimeGenerated, ProcessCommandLine

```
<img width="2476" height="295" alt="POE_QR14" src="https://github.com/user-attachments/assets/67ec2819-d3c6-44a3-a555-7eb03abc7f03" />

---

### 12. Anti-Forensics: Log Tampering

Searched for event log clearing commands since attackers clear event logs in order to destroy forensic evidence and impede investigation efforts. In this case, the attacker cleared event logs in sequence, starting with the Security log (which contains logon events and credential access evidence), followed by System and Application logs.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "wevtutil.exe"
| where ProcessCommandLine has "cl"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="2209" height="398" alt="POE_QR15" src="https://github.com/user-attachments/assets/2331376e-d9b6-47d6-97b2-86eb63556def" />

---

### 13. Impact: Persistence Account

Searched for evidence of account creation since hidden administrator accounts provide alternative access for future campaigns. The backdoor account "support" was created and added to the local Administrators group. It's clear that the account name was chosen to blend in with legitimate IT support accounts, providing persistent administrative access for future operations.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has "/add" 
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc

```
<img width="1766" height="464" alt="POE_QR17" src="https://github.com/user-attachments/assets/d10608a1-c7bf-4d0e-815d-735fbb1c3da1" />

---

### 14. Execution: Malicious Script

Searched for script files created in temporary directories since attackers often use scripting languages to automate their attack chain and identifying the initial attack script reveals the entry point and automation method used in the compromise. The PowerShell script wupdate.ps1 was created in the user's temporary directory and used to automate the attack chain. The filename was disguised to resemble a Windows update utility, enabling execution without raising suspicion.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName endswith ".ps1" or FileName endswith ".bat"
| where ActionType == "FileCreated"
| where FolderPath !contains "Windows Defender" 
| where FolderPath !contains "__PSScriptPolicyTest"
| project TimeGenerated, DeviceName, FolderPath, FileName, InitiatingProcessFileName
| sort by TimeGenerated desc

```
<img width="2535" height="474" alt="POE_QR18" src="https://github.com/user-attachments/assets/eded8066-aa1a-4ffe-9994-78a573bb347f" />

---

### 15. Lateral Movement: Secondary Target & Remote Access Tool

Searched for target systems specified in remote access commands and discovered that the attacker targeted IP address 10.1.0.188 for lateral movement. Since lateral movement targets are selected based on their access to sensitive data or network privileges, identifying these targets can reveal attacker objectives. In addition, the attacker used mstsc.exe (Microsoft Terminal Services Client - the built-in Windows Remote Desktop client) for lateral movement. This Living Off The Land technique allows malicious RDP connections to blend seamlessly with legitimate IT administrative activity.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-18) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("cmdkey.exe", "mstsc.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated desc

```
<img width="2140" height="474" alt="POE_QR19" src="https://github.com/user-attachments/assets/a579c51e-e75b-478e-b81e-b29b879a0fbf" />

---

## Summary

The analysis revealed that the target device, gab-intern-vm, was compromised and the subsequent attacks were disguised as a legitimate support session. The attacker orchestrated a multi-stage attack including the execution of a malicious PowerShell script with bypassed security policies, planted artifacts to create false narratives, clipboard content exfiltration, extensive reconnaissance (i.e., host enumeration, session discovery, storage mapping, connectivity validation, process inventory, and privilege checks), egress validation which involved testing internet connectivity and upload capability, the consolidation of collected artifacts into compressed archives, dual persistence (i.e., scheduled tasks and registry autoruns for long-term access), and fabricated support chat logs. The sophistication of this attack hints at an experienced threat actor with knowledge of defensive detection capabilities.

---

## Timeline

| Time (UTC) | Steps Taken | Action Observed | Key Evidence |
|:--------:|:----------:|:-------------:|:---------------------:|
| 2025-10-09T12:22:27.6588913Z | 1 | Initial Execution Detection | Creation of SupportTool.ps1 and execution with -ExecutionPolicy Bypass |
| 2025-10-09T12:34:59.1260624Z | 2 | Defense Disabling | DefenderTamperArtifact.lnk |
| 2025-10-09T12:50:39.955931Z | 3 | Quick Data Probe | Get-Clipboard command: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" |
| 2025-10-09T12:51:44.3425653Z | 4 | Host Context Reconnaissance | Query session (i.e., qwinsta) |
| 2025-10-09T12:51:18.3848072Z | 5 | Storage Surface Mapping | wmic logicaldisk enumeration |
| 2025-10-09T12:51:31.5692262Z | 6 | Connectivity & Name Resolution Check | RuntimeBroker.exe parent process |
| 2025-10-09T12:50:59.3449917Z | 7 | Interactive Session Discovery | Initiating Process UniqueId: 2533274790397065 |
| 2025-10-09T12:51:57.6866149Z | 8 | Runtime Application Inventory | tasklist.exe |
| 2025-10-09T12:52:14.3135459Z | 9 | Privilege Surface Check | whoami /groups |
| 2025-10-09T12:55:05.7658713Z | 10 | Proof-of-Access & Egress Validation | www.msftconnecttest.com |
| 2025-10-09T12:58:17.4364257Z | 11 | Bundling / Staging Artifacts | C:\Users\Public\ReconArtifacts.zip |
| 2025-10-09T13:00:40.045127Z | 12 | Outbound Transfer Attempt (Simulated) | httpbin.org (100.29.147.161) |
| 2025-10-09T13:01:28.7700443Z | 13 | Scheduled Re-Execution Persistence | SupportToolUpdater (ONLOGON) |
| N/A | 14 | Autorun Fallback Persistence | RemoteAssistUpdater |
| 2025-10-09T13:02:41.5698148Z | 15 | Planted Narrative / Cover Artifact | SupportChat_log.lnk |

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|:--------:|:----------:|:-------------:|:---------------------:|
| T1059.001 | PowerShell | Malicious PowerShell script executed with bypassed execution policy to perform reconnaissance and establish persistence. | Identifies initial execution and subsequent malicious activity via PowerShell commands. |
| T1027 | Obfuscated Files or Information | Attacker used legitimate-sounding file names (SupportTool.ps1, DefenderTamperArtifact.lnk) to disguise malicious intent. | Indicates deceptive naming conventions to evade detection. |
| T1564.004 | NTFS File Attributes | Planted artifacts (DefenderTamperArtifact.lnk, SupportChat_log.txt) created to establish false narratives. | Identifies staged evidence designed to mislead investigators. |
| T1115 | Clipboard Data | PowerShell command used to capture clipboard contents containing potentially sensitive information. | Detects opportunistic data theft from transient sources. |
| T1082 | System Information Discovery | Multiple reconnaissance commands executed including query session, wmic logicaldisk, and tasklist. | Indicates comprehensive host enumeration prior to further exploitation. |
| T1033 | System Owner/User Discovery | Used whoami /groups to enumerate current user privileges and group memberships. | Identifies privilege surface checks to inform escalation attempts. |
| T1049 | System Network Connections Discovery | Network connectivity validated through RuntimeBroker.exe and connectivity tests. | Indicates network reconnaissance and egress validation. |
| T1057 | Process Discovery | Tasklist.exe executed to enumerate running processes and identify security tools. | Detects runtime application inventory for evasion planning. |
| T1567.002 | Exfiltration to Cloud Storage | Staged artifacts bundled into ReconArtifacts.zip and upload capability tested via httpbin.org. | Identifies data staging and exfiltration validation attempts. |
| T1053.005 | Scheduled Task | Created SupportToolUpdater scheduled task with ONLOGON trigger for persistence. | Detects automated re-execution mechanism for long-term access. |
| T1547.001 | Registry Run Keys / Startup Folder | Registry autorun entry RemoteAssistUpdater created as fallback persistence mechanism. | Identifies redundant persistence via registry modification. |
| T1070.009 | Clear Persistence Artifacts | Planted SupportChat_log.txt to create cover story justifying suspicious activity. | Detects fabricated narratives designed to deflect investigation. |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified both the attack techniques (e.g., PowerShell execution, clipboard theft, reconnaissance, persistence mechanisms) and confirmed the sophistication of the attack, with multiple layers of obfuscation and deception.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|:---------------------:|:------:|:--------------:|:-------------:|:-----------:|
| M1038 | Execution Prevention | PowerShell Constrained Language Mode | Implemented PowerShell Constrained Language Mode on intern workstations to restrict unapproved script execution and prevent -ExecutionPolicy Bypass. | Prevents unauthorized script execution by enforcing language restrictions. |
| M1026 | Privileged Account Management | Account Credential Reset | Reset credentials for user account "g4bri3lintern" and implemented mandatory password change with MFA enrollment. | Mitigates unauthorized access risks by invalidating potentially compromised credentials. |
| M1031 | Network Intrusion Prevention | Network Egress Filtering | Blocked outbound connections to testing/debugging services (httpbin.org, example.com) at network perimeter. | Prevents data exfiltration to known testing endpoints. |
| M1047 | Audit | Enhanced PowerShell Logging | Enabled PowerShell script block logging and module logging across all endpoints to capture full command execution context. | Enables early detection of future malicious PowerShell activity and provides forensic evidence. |
| M1018 | User Account Management | Account Lockout Policy Enhancement | Implemented stricter account lockout thresholds for intern accounts after suspicious activity detection. | Adds additional security layer to prevent unauthorized access attempts. |
| M1017 | User Training | Security Awareness Training | Conducted mandatory security awareness retraining for affected user and intern cohort focusing on social engineering and fraudulent support requests. | Reduces likelihood of future social engineering success. |

---

The following response actions were recommended: (1) Isolating the compromised endpoint from the network to prevent further malicious activity; (2) Removing scheduled task SupportToolUpdater and registry persistence entry RemoteAssistUpdater; (3) Deleting malicious artifacts including SupportTool.ps1, DefenderTamperArtifact.lnk, SupportChat_log.txt, and ReconArtifacts.zip; (4) Resetting user credentials and enforcing MFA; (5) Conducting full antimalware scans with updated signatures; (6) Implementing enhanced monitoring for PowerShell execution with bypass parameters; (7) Blocking connections to testing services at network perimeter; (8) Establishing detection rules for clipboard access attempts and reconnaissance commands; (9) Mandatory security awareness retraining for the user.

---
