# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Temporary Directory Execution Detector
# Path:   src/Detection/Process/Detect-TempExecution.ps1
# Description: Instantly flags processes executing out of untrusted user staging areas.
# ==============================================================================

function Detect-TempExecution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        foreach ($Proc in $NormalizedSecurityEvents) {
            # Inspect the main execution binary path
            $Path = $Proc.NewProcessName # e.g., C:\Users\Inioluwa\AppData\Local\Temp\payload.exe

            if (-not [string]::IsNullOrWhiteSpace($Path)) {
                # Target high-risk user-writeable paths
                if ($Path -like "*\AppData\Local\Temp\*" -or 
                    $Path -like "*\Windows\Temp\*" -or 
                    $Path -like "*\Users\Public\*" -or 
                    $Path -like "*\PerfLogs\*") {
                    
                    # Exclude common benign browser updates if they introduce noise
                    if ($Path -like "*GUM*.exe" -or $Path -like "*chrome*") { continue }

                    $DetectedThreats.Add([PSCustomObject]@{
                        Timestamp     = $Proc.TimeGenerated
                        DetectionType = "Suspicious Execution Path"
                        MITRE_ID      = "T1204.002"   # User Execution: Malicious File
                        Severity      = "High"
                        Computer      = $Proc.Computer
                        User          = $Proc.User
                        Description   = "A binary executable was initiated out of a highly volatile, user-writeable temporary staging directory."
                        Evidence      = @{
                            ProcessName   = $Proc.ProcessName
                            ExecutionPath = $Proc.NewProcessName
                            CommandLine   = $Proc.CommandLine
                            ParentProcess = $Proc.ParentProcessName
                            ProcessId     = $Proc.ProcessId
                        }
                    })
                }
            }
        }

        return $DetectedThreats
    }
}