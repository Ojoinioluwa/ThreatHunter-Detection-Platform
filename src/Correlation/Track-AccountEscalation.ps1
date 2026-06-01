# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Account Escalation Analyzer
# Path:   src/Correlator/AccountEscalation.ps1
# Description: Detects immediate administrative privilege assignments to new users.
# ==============================================================================

function Track-AccountEscalation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents,

        [Parameter(Mandatory=$false)]
        [int]$ThresholdMinutes = 15
    )

    process {
        $OrderedEvents = $NormalizedEvents | Sort-Object TimeGenerated
        $TrackedAlerts = [System.Collections.Generic.List[object]]::new()
        $CreatedUsers = @{} 

        foreach ($Log in $OrderedEvents) {
            if ($Log.EventID -eq 4720) {
                $NewUserName = $Log.User
                if (-not [string]::IsNullOrWhiteSpace($NewUserName)) {
                    $CreatedUsers[$NewUserName] = [DateTime]$Log.TimeGenerated
                }
            }

            if ($Log.EventID -eq 4732 -or $Log.EventID -eq 4728) {
                $GroupName = $Log.GroupName
                $AddedUserName = $Log.User
                
                if ($GroupName -like "*Admin*" -or $GroupName -eq "Account Operators") {
                    if ($null -ne $CreatedUsers[$AddedUserName]) {
                        $CreationTime = $CreatedUsers[$AddedUserName]
                        $TimeDiff = ([DateTime]$Log.TimeGenerated - $CreationTime).TotalMinutes

                        if ($TimeDiff -le $ThresholdMinutes) {
                            $TrackedAlerts.Add([PSCustomObject]@{
                                DetectionType       = "Account Creation Plus Privilege Assignment"
                                TargetUser          = $AddedUserName
                                TargetGroup         = $GroupName
                                AccountCreationTime = $CreationTime
                                EscalationTime      = [DateTime]$Log.TimeGenerated
                                TimeDeltaMinutes    = [Math]::Round($TimeDiff, 2)
                                MITRE_ID            = "T1078.002"
                                Severity            = "High"
                            })
                        }
                    }
                }
            }
        }

        return $TrackedAlerts
    }
}