# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Login Sequence Analyzer
# Path:   src/Correlator/LoginSequence.ps1
# Description: Evaluates normalized authentication streams for brute-force patterns.
# ==============================================================================

function Track-LogonSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $OrderedEvents = $NormalizedEvents | Sort-Object TimeGenerated
        $TrackedAlerts = [System.Collections.Generic.List[object]]::new()
        $Tracker = @{}
        
        foreach ($Log in $OrderedEvents) {
            $UserName = $Log.User

            if ([string]::IsNullOrWhiteSpace($UserName) -or $UserName -eq "SYSTEM" -or $UserName -like "*$") {
                continue
            }

            if ($Log.EventID -eq 4625) {
                if ($null -eq $Tracker[$UserName]) {
                    $Tracker[$UserName] = @{
                        Counter   = 1
                        StartDate = [DateTime]$Log.TimeGenerated
                    }
                } else {
                    $TimeDiff = ([DateTime]$Log.TimeGenerated - $Tracker[$UserName].StartDate).TotalMinutes
                    if ($TimeDiff -gt 30) {
                        $Tracker[$UserName].Counter = 1
                        $Tracker[$UserName].StartDate = [DateTime]$Log.TimeGenerated
                    } else {
                        $Tracker[$UserName].Counter++
                    }
                }
            } 
            elseif ($Log.EventID -eq 4624) {
                if ($null -ne $Tracker[$UserName] -and $Tracker[$UserName].Counter -ge 5) {
                    $TrackedAlerts.Add([PSCustomObject]@{
                        DetectionType  = "Brute-Force Authentication Attempt (Success-After-Failure)"
                        NofFailedLogon = $Tracker[$UserName].Counter
                        StartDate      = $Tracker[$UserName].StartDate
                        EndDate        = [DateTime]$Log.TimeGenerated
                        UserName       = $UserName
                        MITRE_ID       = "T1110.001"
                        Severity       = "Critical"
                    })
                }
                $Tracker.Remove($UserName)
            }
        }

        foreach ($Key in $Tracker.Keys) {
            if ($Tracker[$Key].Counter -ge 5) {
                $TrackedAlerts.Add([PSCustomObject]@{
                    DetectionType  = "Active/Ongoing Brute-Force Authentication Attempt"
                    NofFailedLogon = $Tracker[$Key].Counter
                    StartDate      = $Tracker[$Key].StartDate
                    EndDate        = (Get-Date)
                    UserName       = $Key
                    MITRE_ID       = "T1110.001"
                    Severity       = "High"
                })
            }
        }

        return $TrackedAlerts
    }
}