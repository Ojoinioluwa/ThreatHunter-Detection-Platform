function Detect-SecurityGroupModified {
    param([array]$NormalizedSecurityEvents)

    $Alerts = [System.Collections.Generic.List[object]]::new()
    $HighValueGroups = @("Administrators", "Domain Admins", "Enterprise Admins", "Backup Operators")

    foreach ($Events in $NormalizedSecurityEvents) {
        # Direct audit event modifications or cmd utility additions
        $IsGroupModification = ($Events.EventID -eq 4732 -or $Events.EventID -eq 4728)
        $IsCmdlineAddition   = ($Events.EventID -eq 4688 -and $Events.CommandLine -like "*net localgroup*" -and $Events.CommandLine -like "*/add*")

        if ($IsGroupModification -or $IsCmdlineAddition) {
            # Inspect string alignment for priority elevation
            foreach ($Group in $HighValueGroups) {
                if ($Events.CommandLine -like "*$Group*" -or $Events.TargetGroup -eq $Group) {
                    $Alerts.Add([PSCustomObject]@{
                        Timestamp     = $Events.TimeGenerated
                        RuleName        = "Detect-SecurityGroupModified"
                        MitreTechnique  = "T1098" # Account Manipulation
                        TargetUser      = $Events.TargetAccount -or "Injected Member Context"
                        HostingComputer = $Events.Computer
                        Evidence        = "High-value administrative group structure changed: Group Target: $Group. Trace context: $($Events.CommandLine)"
                        TimeDetected    = Get-Date
                    })
                    break
                }
            }
        }
    }
    return $Alerts
}