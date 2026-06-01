function Detect-ProcessHollowing {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()
    $CoreSystemBinaries = @("svchost.exe", "lsass.exe", "services.exe", "lsm.exe")

    foreach ($Events in $NormalizedSecurityEvents) {
        if ($Events.EventID -eq 4688) {
            # Flag core system processes if they spawn from outside the authorized System32 directory
            if ($CoreSystemBinaries -contains $Events.ProcessName) {
                if ($Events.CommandLine -notlike "*C:\Windows\System32\*" -and $Events.CommandLine -notlike "*C:\Windows\SysWOW64\*") {
                    $Alerts.Add([PSCustomObject]@{
                        Timestamp     = $Events.TimeGenerated
                        RuleName        = "Detect-ProcessHollowing"
                        MitreTechnique  = "T1036.005" # Masquerading: Match Legitimate Name or Location
                        TargetUser      = $Events.User
                        HostingComputer = $Events.Computer
                        Evidence        = "Critical system process execution originating from rogue root workspace: Process: $($Events.ProcessName) Cmd: $($Events.CommandLine)"
                        TimeDetected    = Get-Date
                    })
                }
            }
        }
    }
    return $Alerts
}