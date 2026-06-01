# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Synthetic Telemetry Generator
# Path:   src/Collectors/Get-SyntheticTelemetry.ps1
# Description: Generates standardized mock Windows Event data vectors matching 
#              specific target security Event IDs for rule testing.
# ==============================================================================

function Get-SyntheticTelemetry {
    [CmdletBinding()]
    param()

    process {
        Write-Host "[*] Compiling synthetic security log matrix..." -ForegroundColor DarkGray
        $TelemetryBatch = [System.Collections.Generic.List[object]]::new()
        $CurrentTime = Get-Date

        # ----------------------------------------------------------------------
        # 1. PROCESS EXECUTION (EID: 4688) - Obfuscated Flags (Suspicious Evasion)
        # ----------------------------------------------------------------------
        $TelemetryBatch.Add([PSCustomObject]@{
            EventID           = 4688
            Category          = "ProcessExecution"
            TimeGenerated     = $CurrentTime.AddMinutes(-5)
            Computer          = "SIEM-LAB-WKSTN01"
            User              = "Inioluwa"
            ProcessName       = "powershell.exe"
            ParentProcessName = "cmd.exe"
            CommandLine       = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Write-Host 'Triggering ThreatHunter Platform!'; Invoke-Expression # downloadstring iex`""
        })

        # ----------------------------------------------------------------------
        # 2. PROCESS EXECUTION (EID: 4688) - Base64 Encoded Payload (T1027)
        # ----------------------------------------------------------------------
        $TelemetryBatch.Add([PSCustomObject]@{
            EventID           = 4688
            Category          = "ProcessExecution"
            TimeGenerated     = $CurrentTime.AddMinutes(-4)
            Computer          = "SIEM-LAB-WKSTN01"
            User              = "Inioluwa"
            ProcessName       = "powershell.exe"
            ParentProcessName = "explorer.exe"
            CommandLine       = "powershell.exe -Letter -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABoAHIAZQBhAHQAIABIAHUAbgB0AGkAbgBnACAATABpAHYAZQAhACcADwA="
        })

        # ----------------------------------------------------------------------
        # 3. ACCOUNT MANAGEMENT (EID: 4720, 4732) - Rogue Administrator Provisioning
        # ----------------------------------------------------------------------
        $TelemetryBatch.Add([PSCustomObject]@{
            EventID           = 4720
            Category          = "AccountManagement"
            TimeGenerated     = $CurrentTime.AddMinutes(-3)
            Computer          = "SIEM-LAB-DC01"
            User              = "SYSTEM"
            TargetAccount     = "backdoor_admin"
            Description       = "A user account was created."
            CommandLine       = "net user backdoor_admin Password123! /add"
        })

        $TelemetryBatch.Add([PSCustomObject]@{
            EventID           = 4732
            Category          = "AccountManagement"
            TimeGenerated     = $CurrentTime.AddMinutes(-3)
            Computer          = "SIEM-LAB-DC01"
            User              = "SYSTEM"
            TargetAccount     = "backdoor_admin"
            TargetGroup       = "Administrators"
            Description       = "A member was added to a security-enabled local group."
            CommandLine       = "net localgroup administrators backdoor_admin /add"
        })

        # ----------------------------------------------------------------------
        # 4. AUTHENTICATION (EID: 4625) - Brute Force Attempt (Logon Failure)
        # ----------------------------------------------------------------------
        1..3 | ForEach-Object {
            $TelemetryBatch.Add([PSCustomObject]@{
                EventID           = 4625
                Category          = "Authentication"
                TimeGenerated     = $CurrentTime.AddMinutes(-10 + $_)
                Computer          = "SIEM-LAB-DC01"
                User              = "Administrator"
                LogonType         = 3 # Network Logon
                FailureReason     = "Unknown user name or bad password."
                SourceAddress     = "192.168.1.45"
            })
        }

        # ----------------------------------------------------------------------
        # 5. DEFENSE EVASION (EID: 1102) - Clearing Logs
        # ----------------------------------------------------------------------
        $TelemetryBatch.Add([PSCustomObject]@{
            EventID           = 1102
            Category          = "DefenseEvasion"
            TimeGenerated     = $CurrentTime.AddMinutes(-2)
            Computer          = "SIEM-LAB-DC01"
            User              = "Administrator"
            Description       = "The audit log was cleared."
            CommandLine       = "wevtutil cl Security"
        })

        # ----------------------------------------------------------------------
        # 6. SCHEDULED TASK (EID: 106) - Persistence Mechanism Creation
        # ----------------------------------------------------------------------
        $TelemetryBatch.Add([PSCustomObject]@{
            EventID           = 106
            Category          = "ScheduledTask"
            TimeGenerated     = $CurrentTime.AddMinutes(-1)
            Computer          = "SIEM-LAB-WKSTN01"
            User              = "SYSTEM"
            TaskName          = "\Microsoft\Windows\Updater\MaliciousPatch"
            TaskPath          = "C:\Windows\Temp\beacon.exe"
            Description       = "User registered a scheduled task."
        })

        # ----------------------------------------------------------------------
        # 7. REGISTRY MODIFICATION (EID: 4657) - Run Key Persistence Entry
        # ----------------------------------------------------------------------
        $TelemetryBatch.Add([PSCustomObject]@{
            EventID           = 4657
            Category          = "Registry"
            TimeGenerated     = $CurrentTime
            Computer          = "SIEM-LAB-WKSTN01"
            User              = "Inioluwa"
            RegistryKey       = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
            ValueName         = "MaliciousAgent"
            ValueObject       = "C:\Users\Public\payload.exe"
            OperationType     = "New Registry Value Created"
        })

        # Return the collection back to the processing pipeline stream
        return $TelemetryBatch
    }
}