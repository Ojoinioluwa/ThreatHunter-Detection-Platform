# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Suspicious Command-Line Flags Detector
# Path:   src/Detection/Process/Detect-SuspiciousFlags.ps1
# Description: Evaluates arguments for stealth, bypass, or execution masking flags.
# ==============================================================================

function Detect-SuspiciousFlags {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        foreach ($Proc in $NormalizedSecurityEvents) {
            $CmdLine = $Proc.CommandLine

            if (-not [string]::IsNullOrWhiteSpace($CmdLine)) {
                # Look for stealth flags (-w hidden, -WindowStyle Hidden, -NoP, -ExecutionPolicy Bypass)
                if (($CmdLine -like "*-w*hidden*" -or $CmdLine -like "*-windowstyle*hidden*") -or 
                    ($CmdLine -like "*-nop*" -or $CmdLine -like "*-noprofile*") -or 
                    ($CmdLine -like "*-ep*bypass*" -or $CmdLine -like "*-executionpolicy*bypass*") -or 
                    ($CmdLine -like "*downloadstring*" -or $CmdLine -like "*invoke-expression*" -or $CmdLine -like "*iex*")) {
                    
                    $DetectedThreats.Add([PSCustomObject]@{
                        Timestamp     = $Proc.TimeGenerated
                        DetectionType = "Evasive Command-Line Arguments Detected"
                        MITRE_ID      = "T1562.001"   # Impair Defenses: Disable or Modify Tools
                        Severity      = "High"
                        Computer      = $Proc.Computer
                        User          = $Proc.User
                        Description   = "Process arguments contain explicit directives designed to bypass security execution controls or mask user runtime windows."
                        Evidence      = @{
                            ProcessName   = $Proc.ProcessName
                            CommandLine   = $CmdLine
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