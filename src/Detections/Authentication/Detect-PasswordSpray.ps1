# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Password Spraying Detector
# Path:   src/Detection/Authentication/Detect-PasswordSpray.ps1
# Description: Identifies horizontal password spraying across multiple unique accounts.
# ==============================================================================

function Detect-PasswordSpray {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents,

        [Parameter(Mandatory=$false)]
        [int]$UniqueUserThreshold = 5
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        # 1. Filter out service accounts and system noise to isolate actual user targets
        $FailedLogons = $NormalizedSecurityEvents | Where-Object {
            $_.EventID -eq 4625 -and 
            $_.User -notlike "*$" -and 
            $_.User -ne "SYSTEM" -and 
            -not [string]::IsNullOrWhiteSpace($_.User)
        }

        if ($null -eq $FailedLogons -or $FailedLogons.Count -eq 0) {
            return $DetectedThreats
        }

        # 2. Extract all unique users who experienced a login failure in this batch
        $UniqueUsers = $FailedLogons.User | Select-Object -Unique

        # 3. If the number of unique accounts targeted crosses your threshold, trigger!
        if ($UniqueUsers.Count -ge $UniqueUserThreshold) {
            
            # Sort logs to define the temporal boundaries of the spray window
            $SortedLogs = $FailedLogons | Sort-Object TimeGenerated
            $FirstFailure = [DateTime]$SortedLogs[0].TimeGenerated
            $LastFailure  = [DateTime]$SortedLogs[-1].TimeGenerated
            $TimeRangeMinutes = [Math]::Round(($LastFailure - $FirstFailure).TotalMinutes, 2)

            # 4. Generate the high-fidelity Password Spray Alert
            $DetectedThreats.Add([PSCustomObject]@{
                Timestamp     = $LastFailure  # The point where the batch window analysis concludes
                DetectionType = "Horizontal Password Spraying Detection"
                MITRE_ID      = "T1110.003"   # Brute Force: Password Spraying
                Severity      = "High"
                Computer      = $SortedLogs[0].Computer
                User          = "Multiple Accounts" # Explicitly marks this as a horizontal attack
                Description   = "An authentication anomaly was detected where multiple unique user accounts experienced login failures within a synchronized window."
                Evidence      = @{
                    TotalTargetedAccounts = $UniqueUsers.Count
                    TargetedUserList      = $UniqueUsers -join ", "
                    TotalFailedEvents     = $FailedLogons.Count
                    SprayStartTime        = $FirstFailure
                    SprayEndTime          = $LastFailure
                    WindowMinutes         = $TimeRangeMinutes
                    LogonTypesObserved    = ($SortedLogs.LogonType | Select-Object -Unique) -join ", "
                }
            })
        }

        return $DetectedThreats
    }
}