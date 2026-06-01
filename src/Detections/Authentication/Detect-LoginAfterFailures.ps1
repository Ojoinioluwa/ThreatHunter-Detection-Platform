# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Success After Failure Detector
# Path:   src/Detection/Authentication/Detect-LoginAfterFailures.ps1
# Description: Flags successful authentication events that follow a cluster of failures.
# ==============================================================================

function Detect-LoginAfterFailures {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents,

        [Parameter(Mandatory=$false)]
        [int]$MinFailuresBeforeSuccess = 3,

        [Parameter(Mandatory=$false)]
        [int]$MaxWindowMinutes = 15
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        # Sort chronologically to track the exact timeline of events forward
        $OrderedLogs = $NormalizedSecurityEvents | Sort-Object TimeGenerated
        
        # Runtime state tracker to hold failure counts and timestamps per user
        $UserState = @{}

        foreach ($Log in $OrderedLogs) {
            $UserName = $Log.User

            # Filter out machine accounts and empty data noises
            if ([string]::IsNullOrWhiteSpace($UserName) -or $UserName -eq "SYSTEM" -or $UserName -like "*$") {
                continue
            }

            # Case 1: Log is a Failure (4625)
            if ($Log.EventID -eq 4625) {
                if ($null -eq $UserState[$UserName]) {
                    $UserState[$UserName] = @{
                        Count      = 1
                        FirstFault = [DateTime]$Log.TimeGenerated
                        LastFault  = [DateTime]$Log.TimeGenerated
                    }
                } else {
                    # Check if the failure belongs to the same general attack window
                    $TimeSinceFirst = ([DateTime]$Log.TimeGenerated - $UserState[$UserName].FirstFault).TotalMinutes
                    
                    if ($TimeSinceFirst -gt $MaxWindowMinutes) {
                        # Reset window if the gap is too wide
                        $UserState[$UserName].Count = 1
                        $UserState[$UserName].FirstFault = [DateTime]$Log.TimeGenerated
                    } else {
                        $UserState[$UserName].Count++
                    }
                    $UserState[$UserName].LastFault = [DateTime]$Log.TimeGenerated
                }
            }

            # Case 2: Log is a Success (4624)
            elseif ($Log.EventID -eq 4624) {
                $Tracking = $UserState[$UserName]

                if ($null -ne $Tracking -and $Tracking.Count -ge $MinFailuresBeforeSuccess) {
                    
                    # Verify the success happened shortly after the last failure
                    $TimeDelta = ([DateTime]$Log.TimeGenerated - $Tracking.LastFault).TotalMinutes

                    if ($TimeDelta -le $MaxWindowMinutes) {
                        $DetectedThreats.Add([PSCustomObject]@{
                            Timestamp     = $Log.TimeGenerated # The moment of compromise (the success)
                            DetectionType = "Successful Authentication After Brute-Force"
                            MITRE_ID      = "T1110.001"   # Brute Force: Password Guessing
                            Severity      = "Critical"    # Upgraded to Critical because access was achieved
                            Computer      = $Log.Computer
                            User          = $UserName
                            Description   = "An account successfully logged on immediately following a high volume of local authentication failures."
                            Evidence      = @{
                                TargetUser        = $UserName
                                PrecedingFailures = $Tracking.Count
                                AttackStart       = $Tracking.FirstFault
                                CompromiseTime    = $Log.TimeGenerated
                                WindowMinutes     = [Math]::Round(([DateTime]$Log.TimeGenerated - $Tracking.FirstFault).TotalMinutes, 2)
                                LogonType         = $Log.LogonType
                            }
                        })
                    }
                }
                
                # Clear tracking state for this user since a success resets the baseline progression
                $UserState.Remove($UserName)
            }
        }

        return $DetectedThreats
    }
}