<#
=============================================================================================
  PROJECT: Cleanup & Reset for Ransomware Simulation
  PURPOSE: Safely remove simulated encrypted files and restore sandbox test data.
=============================================================================================
#>

[CmdletBinding()]
param (
    [string]$TargetFolder = "C:\Ransomware_Test_Data"
)

Write-Host "[*] Cleaning up simulation artifacts..." -ForegroundColor Yellow

if (Test-Path -Path $TargetFolder) {
    Remove-Item -Path $TargetFolder -Recurse -Force
    Write-Host "[+] Removed simulated folder: $TargetFolder" -ForegroundColor Green
}

$desktopNote = "C:\Users\Public\Desktop\README_RESTORE.txt"
if (Test-Path -Path $desktopNote) {
    Remove-Item -Path $desktopNote -Force
    Write-Host "[+] Removed desktop ransom note." -ForegroundColor Green
}

Write-Host "[+] Cleanup complete. Ready for a new test run." -ForegroundColor Cyan
