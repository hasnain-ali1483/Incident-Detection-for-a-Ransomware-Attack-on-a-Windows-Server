<#
=============================================================================================
  PROJECT: Phase 1 Telemetry & Forwarding Verification Script
  PURPOSE: Validate that Windows Server audit policies, Sysmon, and Splunk Forwarder
           are properly installed and operating prior to attack simulation.
  RUN AS: Administrator on Windows Server
=============================================================================================
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [?] AUDITING & LOGGING VERIFICATION (PHASE 1)" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

$allPass = $true

# 1. Check Sysmon Service
Write-Host "`n[*] 1. Checking Microsoft Sysmon Status..." -ForegroundColor Gray
$sysmon = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
if (-not $sysmon) {
    $sysmon = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
}

if ($sysmon -and $sysmon.Status -eq "Running") {
    Write-Host "  [✔] PASS: Sysmon service is active and running ($($sysmon.Name))." -ForegroundColor Green
} else {
    Write-Host "  [✖] FAIL: Sysmon service is not found or not running." -ForegroundColor Red
    $allPass = $false
}

# 2. Check SIEM Forwarder / Agent Status (Wazuh or Splunk)
Write-Host "`n[*] 2. Checking SIEM Agent Status (Wazuh or Splunk)..." -ForegroundColor Gray
$wazuh = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if (-not $wazuh) { $wazuh = Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue }
$splunk = Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue

if ($wazuh -and $wazuh.Status -eq "Running") {
    Write-Host "  [✔] PASS: Wazuh Agent service is active and running." -ForegroundColor Green
} elseif ($splunk -and $splunk.Status -eq "Running") {
    Write-Host "  [✔] PASS: SplunkForwarder service is active and running." -ForegroundColor Green
} else {
    Write-Host "  [✖] FAIL: Neither Wazuh Agent nor SplunkForwarder service is running." -ForegroundColor Red
    $allPass = $false
}

# 3. Check Command-Line Auditing Registry Key
Write-Host "`n[*] 3. Checking Process Creation Command-Line Auditing..." -ForegroundColor Gray
$cmdLineReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
if ($cmdLineReg -and $cmdLineReg.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Host "  [✔] PASS: ProcessCreationIncludeCmdLine_Enabled is set to 1." -ForegroundColor Green
} else {
    Write-Host "  [!] WARNING: Command-Line Auditing in Event 4688 may not be enabled." -ForegroundColor Yellow
}

# 4. Check PowerShell Script Block Logging Registry Key
Write-Host "`n[*] 4. Checking PowerShell ScriptBlockLogging Policy..." -ForegroundColor Gray
$psLogReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
if ($psLogReg -and $psLogReg.EnableScriptBlockLogging -eq 1) {
    Write-Host "  [✔] PASS: ScriptBlockLogging is enabled (Event ID 4104)." -ForegroundColor Green
} else {
    Write-Host "  [!] WARNING: PowerShell ScriptBlockLogging is not enabled." -ForegroundColor Yellow
}

# 5. Check Sysmon Event Log Availability
Write-Host "`n[*] 5. Testing Sysmon Operational Log..." -ForegroundColor Gray
try {
    $recentSysmon = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
    Write-Host "  [✔] PASS: Sysmon/Operational log exists and is recording events." -ForegroundColor Green
} catch {
    Write-Host "  [✖] FAIL: Unable to read from Microsoft-Windows-Sysmon/Operational log." -ForegroundColor Red
    $allPass = $false
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
if ($allPass) {
    Write-Host " [✔] PHASE 1 TELEMETRY HEALTH: READY FOR ATTACK SIMULATION!" -ForegroundColor Green
} else {
    Write-Host " [!] ATTENTION: Complete missing items above before simulating." -ForegroundColor Yellow
}
Write-Host "==========================================================" -ForegroundColor Cyan
