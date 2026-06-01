# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Live Hybrid Telemetry Simulator
# Path:   scripts/Run-SafeLiveSimulation.ps1
# Description: Automatically creates safe runtime artifacts matching filesystem
#              detection signatures without impacting operational system safety.
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Yellow
Write-Host "         THREATHUNTER SIMULATION MATRIX - TARGET ATTACK SIGNALS        " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Yellow

# 1. Trigger Detect-SuspiciousFlags & Detect-EncodedPowerShell
Write-Host "[!] Spawning safe obfuscated process flags (Bypass/Hidden/Encoded)..." -ForegroundColor Cyan
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Write-Host 'Simulating ThreatHunter Script Activity!';"
powershell.exe -Letter -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABoAHIAZQBhAHQAIABIAHUAbgB0AGkAbgBnACAATABpAHYAZQAhACcADwA=
Start-Sleep -Seconds 1

# 2. Trigger Detect-TempExecution
Write-Host "[!] Spawning safe execution markers pointing to volatile user environments..." -ForegroundColor Cyan
# Passing /? prints help commands cleanly, but generates logs containing \Temp\ strings!
cmd.exe /c "copy /? C:\Users\Public\Downloads" > $null
powershell.exe -Command "Start-Process cmd.exe -ArgumentList '/c echo SafeTest' -WorkingDirectory $env:TEMP"
Start-Sleep -Seconds 1

# 3. Trigger Detect-AdminAssignment & Detect-AccountCreation
Write-Host "[!] Simulating account management and local privilege elevations..." -ForegroundColor Cyan
cmd.exe /c "net user backdoor_admin Password123! /add /?" > $null
cmd.exe /c "net localgroup administrators backdoor_admin /add /?" > $null
Start-Sleep -Seconds 1

# 4. Trigger Detect-OfficeSpawn
Write-Host "[!] Simulating suspicious process births originating from productivity layers..." -ForegroundColor Cyan
# Simulates a macro execution anomaly via a nested tracking comment string
powershell.exe -Command "# EXCEL.EXE process context execution placeholder test script /?" 

Write-Host "`n[+] Full live target generation sequence completed safely!" -ForegroundColor Green