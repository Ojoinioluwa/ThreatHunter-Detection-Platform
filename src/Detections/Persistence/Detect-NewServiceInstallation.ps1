function Detect-NewServiceInstallation {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()

    foreach ($Events in $NormalizedSecurityEvents) {
        # EID 4697 or EID 7045 (New Service Registered) or cmd line manipulation
        $IsServiceAction = ($Events.EventID -eq 4697) -or 
                           ($Events.EventID -eq 4688 -and ($Events.CommandLine -like "*sc*create*" -or $Events.CommandLine -like "*New-Service*"))

        if ($IsServiceAction) {
            $Alerts.Add([PSCustomObject]@{
                Timestamp     = $Events.TimeGenerated
                RuleName        = "Detect-NewServiceInstallation"
                MitreTechnique  = "T1543.003" # Windows Service Manipulation
                TargetUser      = $Events.User
                HostingComputer = $Events.Computer
                Evidence        = "New system daemon registration event monitored: $($Events.CommandLine)"
                TimeDetected    = Get-Date
            })
        }
    }
    return $Alerts
}