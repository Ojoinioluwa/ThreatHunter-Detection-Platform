# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Privileged Logon Detector
# Path:   src/Detection/Authentication/Detect-PrivilegedLogon.ps1
# Description: Flags successful authentications by high-value administrative accounts.
# ==============================================================================

function Detect-PrivilegedLogon {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        # Define high-value usernames that should always be monitored when accessing systems
        $PrivilegedUsers = @(
            "Administrator",
            "DomainAdmin",
            "EnterpriseAdmin",
            "svc-backup",
            "krbtgt"
        )

        foreach ($Log in $NormalizedSecurityEvents) {
            # Event ID 4624: An account was successfully logged on
            if ($Log.EventID -eq 4624) {
                
                $IsPrivileged = $false
                $Reason = ""

                # Match Condition 1: Is the username in our static high-value list?
                if ($PrivilegedUsers -contains $Log.User) {
                    $IsPrivileged = $true
                    $Reason = "Username matches a monitored high-privilege account definition."
                }
                
                # Match Condition 2: Built-in Local Admin SID Check (Ends with RID -500)
                # This catches the true administrator account even if the attacker renamed it.
                elseif ($null -ne $Log.TargetUserSid -and $Log.TargetUserSid -like "*-500") {
                    $IsPrivileged = $true
                    $Reason = "Account Security ID (SID) maps directly to the built-in Administrator RID-500 profile."
                }

                # If a match is confirmed, evaluate the logon severity context
                if ($IsPrivileged) {
                    
                    # Elevate severity if the privileged account is coming over the network or RDP
                    $AlertSeverity = "Medium"
                    if ($Log.LogonType -eq 3 -or $Log.LogonType -eq 10) {
                        $AlertSeverity = "High"
                    }

                    $DetectedThreats.Add([PSCustomObject]@{
                        Timestamp     = $Log.TimeGenerated
                        DetectionType = "Privileged Account Authentication Success"
                        MITRE_ID      = "T1078.001"   # Valid Accounts: Default Accounts
                        Severity      = $AlertSeverity
                        Computer      = $Log.Computer
                        User          = $Log.User     # The privileged user who logged in
                        Description   = "A successful authentication sequence was recorded for a highly privileged or critical infrastructure account."
                        Evidence      = @{
                            TargetUser    = $Log.User
                            TargetUserSid = $Log.TargetUserSid
                            LogonType     = $Log.LogonType     # e.g., 2 (Interactive), 3 (Network), 10 (RDP)
                            IpAddress     = $Log.IpAddress     # Captured during flattening by your collector
                            MatchReason   = $Reason
                            EventID       = $Log.EventID
                        }
                    })
                }
            }
        }

        return $DetectedThreats
    }
}