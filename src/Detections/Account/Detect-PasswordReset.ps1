# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Password Reset Detector
# Path:   src/Detection/Account/Detect-PasswordReset.ps1
# Description: Instantly flags an attempt to reset an account's password.
# ==============================================================================

function Detect-PasswordReset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        foreach ($Log in $NormalizedSecurityEvents) {
            # Event ID 4724: An attempt was made to reset an account's password
            if ($Log.EventID -eq 4724) {
                    
                $DetectedThreats.Add([PSCustomObject]@{
                    Timestamp     = $Log.TimeGenerated
                    DetectionType = "User Account Password Reset Attempt"
                    MITRE_ID      = "T1098"      # Account Manipulation
                    Severity      = "Medium"     # Medium severity because helpdesks do this routinely
                    Computer      = $Log.Computer
                    User          = $Log.User    # The actor/admin who reset the password
                    Description   = "An explicit administrative password reset attempt was recorded for a target user account."
                    Evidence      = @{
                        TargetUser = $Log.TargetUser # The account whose password was reset
                        EventID    = $Log.EventID
                        ProcessId  = $Log.ProcessId
                    }
                })
            }
        }

        return $DetectedThreats
    }
}