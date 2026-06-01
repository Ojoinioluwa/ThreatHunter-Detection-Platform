function Detect-LsassHandleRequest {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()

    foreach ($Events in $NormalizedSecurityEvents) {
        # EID 4656 (Handle requested) or EID 4688 checking for process memory dumps
        if ($Events.EventID -eq 4656 -and $Events.ObjectName -like "*lsass.exe*") {
            $Alerts.Add([PSCustomObject]@{
                Timestamp     = $Events.TimeGenerated
                RuleName        = "Detect-LsassHandleRequest"
                MitreTechnique  = "T1003.001" # LSASS Memory Dumping
                TargetUser      = $Events.User
                HostingComputer = $Events.Computer
                Evidence        = "Direct security access handle requested against the LSASS subsystem core process."
                TimeDetected    = Get-Date
            })
        }
        elseif ($Events.EventID -eq 4688 -and ($Events.CommandLine -like "*comsvcs.dll*MiniDump*" -or $Events.CommandLine -like "*procdump*")) {
            $Alerts.Add([PSCustomObject]@{
                Timestamp     = $Events.TimeGenerated
                RuleName        = "Detect-LsassHandleRequest"
                MitreTechnique  = "T1003.001" # LSASS Memory Dumping
                TargetUser      = $Events.User
                HostingComputer = $Events.Computer
                Evidence        = "Process creation pattern matches LSASS memory harvest execution string: $($Events.CommandLine)"
                TimeDetected    = Get-Date
            })
        }
    }
    return $Alerts
}