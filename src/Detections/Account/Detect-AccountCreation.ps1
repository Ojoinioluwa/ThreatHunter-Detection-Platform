# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Account Creation Detector
# Path:   src/Detection/Account/Detect-AccountCreation.ps1
# Description: Instantly flags the creation of any new local or domain user account.
# ==============================================================================

function Detect-AccountCreation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        foreach ($Log in $NormalizedSecurityEvents) {
            # Event ID 4720: A user account was created
            if ($Log.EventID -eq 4720) {
                    
                $DetectedThreats.Add([PSCustomObject]@{
                    Timestamp     = $Log.TimeGenerated
                    DetectionType = "User Account Created"
                    MITRE_ID      = "T1136.001" # Create Account: Local Account
                    Severity      = "Medium"     # Medium severity because it could be normal admin activity
                    Computer      = $Log.Computer
                    User          = $Log.User    # The actor/admin who created the account
                    Description   = "A new local or domain operating system account was provisioned on the host."
                    Evidence      = @{
                        TargetUser = $Log.TargetUser # The actual account name that was created
                        EventID    = $Log.EventID
                        ProcessId  = $Log.ProcessId
                    }
                })
            }
        }

        return $DetectedThreats
    }
}