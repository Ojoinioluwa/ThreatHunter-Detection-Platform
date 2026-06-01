function Detect-LivingOffTheLandBinaries {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()

    foreach ($Events in $NormalizedSecurityEvents) {
        if ($Events.EventID -eq 4688) {
            $Cmd = $Events.CommandLine
            
            # Identify egress utility triggers or atypical download execution syntax paths
            $IsLolbasDownload = ($Events.ProcessName -eq "certutil.exe" -and ($Cmd -like "*-urlcache*" -or $Cmd -like "*-split*")) -or 
                                ($Events.ProcessName -eq "bitsadmin.exe" -and ($Cmd -like "*/transfer*" -or $Cmd -like "*/download*"))

            if ($IsLolbasDownload) {
                $Alerts.Add([PSCustomObject]@{
                    Timestamp     = $Events.TimeGenerated
                    RuleName        = "Detect-LivingOffTheLandBinaries"
                    MitreTechnique  = "T1105" # Ingress Tool Transfer
                    TargetUser      = $Events.User
                    HostingComputer = $Events.Computer
                    Evidence        = "Native administrative OS binary utilized to execute file ingress cradle requests: $Cmd"
                    TimeDetected    = Get-Date
                })
            }
        }
    }
    return $Alerts
}