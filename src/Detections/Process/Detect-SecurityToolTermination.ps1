function Detect-SecurityToolTermination {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()
    $SecurityKeywords = @("sysmon", "defender", "wevtutil", "cybereason", "crowdstrike", "sentinelone")

    foreach ($Events in $NormalizedSecurityEvents) {
        # EID 4689: Process was terminated
        if ($Events.EventID -eq 4689) {
            foreach ($Keyword in $SecurityKeywords) {
                if ($Events.ProcessName -like "*$Keyword*") {
                    $Alerts.Add([PSCustomObject]@{
                        Timestamp     = $Events.TimeGenerated
                        RuleName        = "Detect-SecurityToolTermination"
                        MitreTechnique  = "T1562.001" # Impair Defenses: Disable or Modify Tools
                        TargetUser      = "Unknown (Kernel Kill Handle)"
                        HostingComputer = $Events.Computer
                        Evidence        = "Security ecosystem defense process killed unexpectedly: Binary identity context: $($Events.ProcessName)"
                        TimeDetected    = Get-Date
                    })
                    break
                }
            }
        }
    }
    return $Alerts
}