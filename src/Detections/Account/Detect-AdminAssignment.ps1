# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Administrative Privilege Assignment Detector
# Path:   src/Detection/Account/Detect-AdminAssignment.ps1
# Description: Instantly flags any account additions to high-privilege administrative groups.
# ==============================================================================

function Detect-AdminAssignment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        # Define an array of high-value administrative target groups to monitor
        $PrivilegedGroups = @(
            "Administrators",
            "Domain Admins",
            "Enterprise Admins",
            "Account Operators",
            "Backup Operators"
        )

        foreach ($Log in $NormalizedSecurityEvents) {
            # Target group membership addition event IDs
            if ($Log.EventID -eq 4732 -or $Log.EventID -eq 4728) {
                
                # Check if the group being modified is in our high-privilege list
                if ($PrivilegedGroups -contains $Log.GroupName) {
                    
                    $DetectedThreats.Add([PSCustomObject]@{
                        Timestamp     = $Log.TimeGenerated
                        DetectionType = "Direct Administrative Privilege Assignment"
                        MITRE_ID      = "T1078.002" # Valid Accounts: Domain Accounts
                        Severity      = "High"
                        Computer      = $Log.Computer
                        User          = $Log.User  # The admin/operator who granted the privilege
                        Description   = "A user account was directly added to a highly privileged administrative security group."
                        Evidence      = @{
                            TargetUser  = $Log.TargetUser # The lucky account that just got admin rights
                            TargetGroup = $Log.GroupName  # The specific group (e.g., Domain Admins)
                            EventID     = $Log.EventID
                            ProcessId   = $Log.ProcessId
                        }
                    })
                }
            }
        }

        return $DetectedThreats
    }
}
