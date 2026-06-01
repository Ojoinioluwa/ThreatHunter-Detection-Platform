# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Brute Force Volume Detector
# Path:   src/Detection/Authentication/Detect-Bruteforce.ps1
# Description: Analyzes a batch of logs to find users with high-volume login failures.
# ==============================================================================

function Detect-Bruteforce {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents,

        [Parameter(Mandatory=$false)]
        [int]$FailureThreshold = 5
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        # 1. Filter for only failed logons (4625) and filter out service/system accounts
        $FailedLogons = $NormalizedSecurityEvents | Where-Object {
            $_.EventID -eq 4625 -and 
            $_.User -notlike "*$" -and 
            $_.User -ne "SYSTEM" -and 
            -not [string]::IsNullOrWhiteSpace($_.User)
        }

        # 2. Group the failures by username so we can analyze each user individually
        $GroupedFailures = $FailedLogons | Group-Object -Property User

        foreach ($Group in $GroupedFailures) {
            $CurrentCount = $Group.Count

            # 3. Check if the user's failed attempts cross your threshold of 5
            if ($CurrentCount -ge $FailureThreshold) {
                
                # Sort chronologically to get the exact time range of the attack
                $SortedLogs = $Group.Group | Sort-Object TimeGenerated
                $FirstFailure = [DateTime]$SortedLogs[0].TimeGenerated
                $LastFailure  = [DateTime]$SortedLogs[-1].TimeGenerated
                
                # Calculate the time delta
                $TimeRangeMinutes = [Math]::Round(($LastFailure - $FirstFailure).TotalMinutes, 2)

                # 4. Generate the proper Brute Force Alert
                $DetectedThreats.Add([PSCustomObject]@{
                    Timestamp     = $LastFailure  # The moment the threshold was crossed/latest event
                    DetectionType = "Authentication Brute-Force Detection"
                    MITRE_ID      = "T1110.001"   # Brute Force: Password Guessing
                    Severity      = "High"
                    Computer      = $SortedLogs[0].Computer
                    User          = $Group.Name   # The target username under attack
                    Description   = "A high volume of failed authentication attempts was detected against a single user account within a short window."
                    Evidence      = @{
                        TargetUser         = $Group.Name
                        TotalFailedLogons  = $CurrentCount
                        AttackStartTime    = $FirstFailure
                        AttackEndTime      = $LastFailure
                        TimeRangeMinutes   = $TimeRangeMinutes
                        LogonTypesObserved = ($SortedLogs.LogonType | Select-Object -Unique) -join ", "
                    }
                })
            }
        }

        return $DetectedThreats
    }
}