function Detect-ExplicitCredentialsUse {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()

    foreach ($Events in $NormalizedSecurityEvents) {
        # EID 4648: A logon was attempted using explicit credentials (runas / alternate handles)
        if ($Events.EventID -eq 4648 -or ($Events.EventID -eq 4688 -and $Events.CommandLine -like "*runas*/*user*")) {
            $Alerts.Add([PSCustomObject]@{
                Timestamp     = $Events.TimeGenerated
                RuleName        = "Detect-ExplicitCredentialsUse"
                MitreTechnique  = "T1078" # Valid Accounts
                TargetUser      = $Events.User
                HostingComputer = $Events.Computer
                Evidence        = "Process or logon layer attempted explicit credential validation swap context: $($Events.CommandLine)"
                TimeDetected    = Get-Date
            })
        }
    }
    return $Alerts
}