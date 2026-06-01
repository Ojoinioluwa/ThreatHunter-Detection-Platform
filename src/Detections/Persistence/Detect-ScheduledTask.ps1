# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Scheduled Task Modification Detector
# Path:   src/Detection/Host/Detect-ScheduledTask.ps1
# Description: Instantly flags the creation or execution of anomalous scheduled tasks.
# ==============================================================================

function Detect-ScheduledTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()
        # Write-Host $NormalizedSecurityEvents

        foreach ($Task in $NormalizedSecurityEvents) {
            
            # Sub-Rule A: Watch for new task registrations targeting suspicious bins or paths
            if ($Task.EventID -eq 106) {
                if ($Task.TaskPath -like "*\Temp\*" -or $Task.TaskPath -like "*\Users\Public\*" -or $Task.TaskName -like "*svch0st*") {
                    
                    $DetectedThreats.Add([PSCustomObject]@{
                        Timestamp     = $Task.TimeGenerated
                        DetectionType = "Suspicious Scheduled Task Registration"
                        MITRE_ID      = "T1053.005"   # Scheduled Task/Job: Scheduled Task
                        Severity      = "High"
                        Computer      = $Task.Computer
                        User          = $Task.User
                        Description   = "A new scheduled task was registered pointing to an untrusted file system environment or using deceptive naming schemas."
                        Evidence      = @{
                            TaskName  = $Task.TaskName
                            TaskPath  = $Task.TaskPath
                            EventID   = $Task.EventID
                            ProcessId = $Task.ProcessId
                        }
                    })
                }
            }

            # Sub-Rule B: Watch for task execution triggers running administrative tools
            elseif ($Task.EventID -eq 200) {
                if ($Task.ActionName -like "*powershell*" -or $Task.ActionName -like "*cmd.exe*" -or $Task.ActionName -like "*certutil*") {
                    
                    $DetectedThreats.Add([PSCustomObject]@{
                        Timestamp     = $Task.TimeGenerated
                        DetectionType = "Privileged Scheduled Task Execution"
                        MITRE_ID      = "T1053.005"
                        Severity      = "High"
                        Computer      = $Task.Computer
                        User          = "NT AUTHORITY\SYSTEM"
                        Description   = "An active scheduled task executed an action launching native script execution environment applications."
                        Evidence      = @{
                            TaskName   = $Task.TaskName
                            ActionName = $Task.ActionName
                            EventID    = $Task.EventID
                        }
                    })
                }
            }
        }

        return $DetectedThreats
    }
}