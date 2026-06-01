function Detect-AccessibilityFeatureAbuse {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()
    $AccessibilityBinaries = @("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe")

    foreach ($Events in $NormalizedSecurityEvents) {
        if ($Events.EventID -eq 4688) {
            foreach ($Binary in $AccessibilityBinaries) {
                # Alert if accessibility binary spawns an atypical interpreter or is spawned atypically
                if ($Events.ProcessName -eq $Binary -and ($Events.CommandLine -like "*cmd.exe*" -or $Events.CommandLine -like "*powershell*")) {
                    $Alerts.Add([PSCustomObject]@{
                        Timestamp     = $Events.TimeGenerated
                        RuleName        = "Detect-AccessibilityFeatureAbuse"
                        MitreTechnique  = "T1546.015" # Accessibility Features
                        TargetUser      = $Events.User
                        HostingComputer = $Events.Computer
                        Evidence        = "Exploitation trace: Accessibility binary execution associated with shell environment runtime: $($Events.CommandLine)"
                        TimeDetected    = Get-Date
                    })
                    break
                }
            }
        }
    }
    return $Alerts
}