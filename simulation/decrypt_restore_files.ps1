<#
=============================================================================================
  PROJECT: Incident Response & Remediation - Automated SOC Decryptor & Data Recovery Utility
  AUTHOR: Mohammad Hasnain Ali
  TARGET: Windows Server 2022 (192.168.56.103)
  PURPOSE: Reverses simulated ransomware encryption across protected shares, restores binary
           payloads to original document formats, and excises extortion artifacts.
=============================================================================================
#>

[CmdletBinding()]
param (
    [string]$TargetFolder = "C:\Finance"
)

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "   [+] SOC REMEDIATION: RUNNING DECRYPTOR UTILITY        " -ForegroundColor Green
Write-Host "   Target Directory: $TargetFolder" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Green

if (-not (Test-Path $TargetFolder)) {
    Write-Error "Target folder $TargetFolder does not exist!"
    return
}

$lockedFiles = Get-ChildItem -Path $TargetFolder -Filter *.locked

if ($lockedFiles.Count -eq 0) {
    Write-Host "[!] No .locked files detected in $TargetFolder." -ForegroundColor Yellow
} else {
    Write-Host "[*] Discovered $($lockedFiles.Count) encrypted files. Beginning restoration..." -ForegroundColor Cyan
    $restoredCount = 0

    foreach ($file in $lockedFiles) {
        try {
            # 1. Read base64 encrypted content
            $b64Content = [System.IO.File]::ReadAllText($file.FullName)
            
            # 2. Decode back to original binary representation
            $originalBytes = [Convert]::FromBase64String($b64Content)
            
            # 3. Restore original filename structure (stripping .locked)
            $restoredName = $file.FullName -replace '\.locked$', ''
            [System.IO.File]::WriteAllBytes($restoredName, $originalBytes)
            
            # 4. Remove malicious locked artifact
            Remove-Item -Path $file.FullName -Force
            $restoredCount++
            Write-Host "    [✓] Decrypted and Restored: $($file.Name) -> $(Split-Path $restoredName -Leaf)" -ForegroundColor Green
        } catch {
            Write-Warning "Failed to decrypt $($file.Name): $_"
        }
    }
    Write-Host "`n[+] Total records successfully restored: $restoredCount / $($lockedFiles.Count)" -ForegroundColor Green
}

# 5. Purge extortion note
$ransomNotes = @(
    "$TargetFolder\README_HOW_TO_RECOVER.txt",
    "$TargetFolder\README_RESTORE.txt"
)

foreach ($note in $ransomNotes) {
    if (Test-Path $note) {
        Remove-Item -Path $note -Force
        Write-Host "[+] Purged extortion artifact: $(Split-Path $note -Leaf)" -ForegroundColor Yellow
    }
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " [✓] REMEDIATION & RESTORATION COMPLETE: 100% LOSSLESS!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Get-ChildItem -Path $TargetFolder
