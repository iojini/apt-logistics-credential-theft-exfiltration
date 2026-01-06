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

### 4. Defence Evasion: File Extension Exclusions

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

### 9. Persistence: Scheduled Task Target

Searched for privilege enumeration commands and discovered that the first privilege check occurred at 2025-10-09T12:52:14.3135459Z. The attacker used whoami /groups to enumerate the group memberships of the user in an attempt to understand what privileges they had. This allows the attacker to decide whether they could proceed with their current access level or if they need to attempt privilege escalation.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("whoami")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="1918" height="727" alt="Query9 Results" src="https://github.com/user-attachments/assets/3fc9d937-1fc6-4fa5-b5e1-2d6357adfaaa" />

---

### 10. Proof-of-Access and Egress Validation

Searched for outbound connectivity tests and identified that the first outbound destination contacted was www.msftconnecttest.com which is a Microsoft connectivity test endpoint used to validate internet connectivity. In other words, the attacker used a legitimate Microsoft connectivity test service to validate outbound internet access before attempting data exfiltration.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09 12:50:00) .. datetime(2025-10-09 13:50:00))
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, RemoteUrl, RemoteIP, InitiatingProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="2551" height="382" alt="Query10 Results" src="https://github.com/user-attachments/assets/25055020-f770-4c80-8b29-1275aa3af22f" />

---

### 11. Bundling and Staging Artifacts 

Searched for signs of file consolidation and packaging and identified that the first folder used for bundling the collected data was: C:\Users\Public\ReconArtifacts.zip.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09 12:50:00) .. datetime(2025-10-09 13:50:00))
| where DeviceName == "gab-intern-vm"
| where FileName endswith ".zip"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="2724" height="605" alt="Query11 Results" src="https://github.com/user-attachments/assets/d081aed5-7724-4a7e-b5d7-b70c4c29cf05" />

---
### 12. Outbound Transfer Attempt

Searched for unusual outbound connections and found that a connection to 100.29.147.161 (i.e., httpbin.org) occurred at 1:00:40 PM. Note: httpbin.org is a publicly available testing service used to validate HTTP upload capability.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-10-09 13:00:00) .. datetime(2025-10-09 14:00:00))
| where DeviceName == "gab-intern-vm"
| where RemoteUrl != ""
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="2443" height="926" alt="Query12 Results" src="https://github.com/user-attachments/assets/68136d27-1688-4020-8571-b83102914bec" />

---

### 13. Scheduled Re-execution Persistence

Searched for scheduled task creation commands and found a scheduled task named SupportToolUpdater configured to run ONLOGON. This ensures that SupportTool.ps1 runs automatically every time the user logs in. Additional parameters include -WindowStyle (set to Hidden) and -ExecutionPolicy (set to Bypass), allowing it to execute while avoiding detection and bypassing security.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "schtasks"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="2783" height="323" alt="Query13 Results" src="https://github.com/user-attachments/assets/d1bdcde3-14ad-45f3-8a55-6c8c0f11e292" />

---

### 14. Autorun Fallback Persistence

Searched for registry modifications for autorun fallback persistence. Although DeviceRegistryEvents showed no results, the attacker created a registry value named RemoteAssistUpdater as part of their fallback persistence mechanism. In other words, the attacker created redundant persistence so if the primary persistence mechanism (i.e., the scheduled task) is removed or disabled, this will keep them in the system.

**Query used to locate events:**

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where RegistryKey contains "run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```
---

### 15. Planted Narrative and Cover Artifact

Searched for explanatory artifacts created around the time of the suspicious activity that might serve as planted narratives and identified that the file name of the artifact left behind was SupportChat_log.lnk.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09 12:20:00) .. datetime(2025-10-09 14:00:00))
| where DeviceName == "gab-intern-vm"
| where FileName contains "Support"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="2470" height="659" alt="Query15 Results" src="https://github.com/user-attachments/assets/b5ce65ce-b182-4f81-bc4c-7cf78cdd2618" />

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
