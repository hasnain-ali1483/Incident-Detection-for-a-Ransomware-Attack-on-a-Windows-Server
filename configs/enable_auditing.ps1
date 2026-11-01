<#
=============================================================================================
  PROJECT: Enable Windows Advanced Audit Policies & PowerShell Logging
  AUTHOR: Incident Detection Project
  RUN AS: Administrator
=============================================================================================
#>

Write-Host "[*] Enabling Advanced Windows Audit Policies..." -ForegroundColor Cyan

# 1. Enable Detailed Tracking: Process Creation (Event ID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# 2. Enable Command Line Auditing in Event ID 4688
$auditRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $auditRegKey)) {
    New-Item -Path $auditRegKey -Force | Out-Null
}
Set-ItemProperty -Path $auditRegKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Host "  [+] Process Creation with Command-Line Auditing enabled." -ForegroundColor Green

# 3. Enable Object Access (File System) Auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable
Write-Host "  [+] File System Auditing enabled." -ForegroundColor Green

# 4. Enable Logon & Account Lockout Auditing (Event IDs 4624, 4625)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
Write-Host "  [+] Logon/Authentication Auditing enabled." -ForegroundColor Green

# 5. Enable PowerShell Script Block Logging (Event ID 4104)
$psAuditKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psAuditKey)) {
    New-Item -Path $psAuditKey -Force | Out-Null
}
Set-ItemProperty -Path $psAuditKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-Host "  [+] PowerShell Script Block Logging (4104) enabled." -ForegroundColor Green

Write-Host "`n[✔] Auditing Configuration Complete!" -ForegroundColor Green
