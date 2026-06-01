function Detect-AnomalousLogonType {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()

    foreach ($Events in $NormalizedSecurityEvents) {
        # Focus strictly on successful logons (EID 4624)
        if ($Events.EventID -eq 4624) {
            $LogonType = $Events.LogonType
            $Username  = $Events.User

            # Flag anomalous combinations:
            # - Interactive logons (Type 2) or RDP (Type 10) by system/service accounts
            # - Network logons (Type 3) targeting default local administrator profiles
            $IsAnomalous = (($LogonType -eq 2 -or $LogonType -eq 10) -and ($Username -like "*$*" -or $Username -eq "SYSTEM")) -or 
                           ($LogonType -eq 3 -and $Username -eq "Administrator")

            if ($IsAnomalous) {
                $Alerts.Add([PSCustomObject]@{
                    Timestamp     = $Events.TimeGenerated
                    RuleName        = "Detect-AnomalousLogonType"
                    MitreTechnique  = "T1078" # Valid Accounts
                    TargetUser      = $Username
                    HostingComputer = $Events.Computer
                    Evidence        = "Suspicious logon execution. Account '$Username' utilized Logon Type: $LogonType"
                    TimeDetected    = Get-Date
                })
            }
        }
    }
    return $Alerts
}