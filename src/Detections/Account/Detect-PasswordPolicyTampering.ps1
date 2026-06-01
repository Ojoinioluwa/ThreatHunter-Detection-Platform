function Detect-PasswordPolicyTampering {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()

    foreach ($Events in $NormalizedSecurityEvents) {
        # EID 4739: Domain policy changes or net accounts execution flags
        if ($Events.EventID -eq 4739 -or ($Events.EventID -eq 4688 -and $Events.CommandLine -like "*net accounts*")) {
            $Alerts.Add([PSCustomObject]@{
                Timestamp     = $Events.TimeGenerated
                RuleName        = "Detect-PasswordPolicyTampering"
                MitreTechnique  = "T1089" # Disabling Security Controls
                TargetUser      = $Events.User
                HostingComputer = $Events.Computer
                Evidence        = "System password parameters or execution thresholds altered: $($Events.CommandLine)"
                TimeDetected    = Get-Date
            })
        }
    }
    return $Alerts
}