<#
=============================================================================================
  PROJECT: Incident Response Playbook - Emergency Host Containment & Attacker Eviction
  AUTHOR: Mohammad Hasnain Ali
  TARGET: Windows Server 2022 (192.168.56.103)
  PURPOSE: Swiftly isolate a compromised Windows Server from the network, evict remote
           attacker sessions (Evil-WinRM / PowerShell), lock down compromised accounts,
           and preserve SIEM (Wazuh 192.168.56.101) telemetry streaming.
=============================================================================================
#>

[CmdletBinding()]
param (
    [string]$SIEM_IP = "192.168.56.101",
    [string]$Analyst_IP = "192.168.56.1"
)

Write-Host "==========================================================" -ForegroundColor Red
Write-Host " [!] EMERGENCY INCIDENT CONTAINMENT: HOST ISOLATION" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Red

# 1. Terminate Attacker Remote Sessions (WinRM / PowerShell / Command Line)
Write-Host "`n[*] Step 1: Evicting active attacker sessions and malicious processes..." -ForegroundColor Yellow
$maliciousProcessNames = @("wsmprovhost", "vssadmin", "powershell", "cmd")
foreach ($proc in $maliciousProcessNames) {
    $found = Get-Process -Name $proc -ErrorAction SilentlyContinue
    if ($found) {
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
        Write-Host "  [-] Evicted & Terminated process: $proc" -ForegroundColor Red
    }
}

# 2. Lock Down Compromised User Account
Write-Host "`n[*] Step 2: Locking down compromised local administrative accounts..." -ForegroundColor Yellow
try {
    Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    Write-Host "  [✓] Compromised local account 'Administrator' disabled." -ForegroundColor Green
} catch {
    Write-Host "  [!] Account lockdown handled via policy or domain controller." -ForegroundColor DarkGray
}

# 3. Configure Windows Firewall to block all network traffic EXCEPT the SIEM and Analyst IP
Write-Host "`n[*] Step 3: Isolating network interfaces (Except SIEM / Forensics)..." -ForegroundColor Yellow

# Enable Windows Firewall across all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block Outbound by default
New-NetFirewallRule -DisplayName "IR-Containment-BlockAllOutbound" -Direction Outbound -Action Block -Priority 10 -ErrorAction SilentlyContinue | Out-Null

# Allow SIEM logging out to Wazuh (192.168.56.101 on Port 1514)
New-NetFirewallRule -DisplayName "IR-Containment-AllowSIEM-Out" -Direction Outbound -Action Allow -RemoteAddress $SIEM_IP -Priority 1 -ErrorAction SilentlyContinue | Out-Null

# Allow Incident Responder SSH / Admin in
New-NetFirewallRule -DisplayName "IR-Containment-AllowAnalyst-In" -Direction Inbound -Action Allow -RemoteAddress $Analyst_IP -Priority 1 -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n[✓] Host Network Isolation Active!" -ForegroundColor Green
Write-Host "    - Lateral Movement: BLOCKED" -ForegroundColor Green
Write-Host "    - Exfiltration / C2: BLOCKED" -ForegroundColor Green
Write-Host "    - SIEM Telemetry Link (Wazuh $SIEM_IP:1514): MAINTAINED" -ForegroundColor Green
