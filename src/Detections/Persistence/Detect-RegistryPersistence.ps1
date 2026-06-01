# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Registry Persistence Detector
# Path:   src/Detection/Host/Detect-RegistryPersistence.ps1
# Description: Instantly flags modifications to standard Windows Run and Autorun keys.
# ==============================================================================

function Detect-RegistryPersistence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        foreach ($Reg in $NormalizedSecurityEvents) {
            # Event ID 4657: A registry value was modified
            if ($Reg.EventID -eq 4657) {
                
                # Check if the change happened inside an active Run or RunOnce hive
                if ($Reg.RegistryKey -like "*\CurrentVersion\Run*" -or $Reg.RegistryKey -like "*\CurrentVersion\*\Run*") {
                    
                    # Highlight suspicious execution utilities inside the string
                    $Severity = "Medium"
                    if ($Reg.NewValueData -like "*powershell*" -or $Reg.NewValueData -like "*cmd.exe*" -or $Reg.NewValueData -like "*iex*") {
                        $Severity = "High"
                    }

                    $DetectedThreats.Add([PSCustomObject]@{
                        Timestamp     = $Reg.TimeGenerated
                        DetectionType = "Registry Autostart Modification"
                        MITRE_ID      = "T1547.001"   # Boot or Logon Autostart Execution: Registry Run Keys
                        Severity      = $Severity
                        Computer      = $Reg.Computer
                        User          = $Reg.User     # The operator/process that changed the key
                        Description   = "A modification or creation event was observed within a critical system startup registry hive."
                        Evidence      = @{
                            RegistryKey   = $Reg.RegistryKey
                            ValueName     = $Reg.ValueName
                            NewValueData  = $Reg.NewValueData
                            OperationType = $Reg.OperationType
                            ProcessId     = $Reg.ProcessId
                        }
                    })
                }
            }
        }

        return $DetectedThreats
    }
}