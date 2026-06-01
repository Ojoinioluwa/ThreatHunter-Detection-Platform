# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Persistence Chain Correlator
# Path:   src/Correlator/PersistenceChain.ps1
# Description: Correlates Registry Run keys and Task Scheduler configurations 
#              to detect multi-stage host persistence mechanics.
# ==============================================================================

function Track-PersistenceChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)] [array]$RegistryEvents,
        [Parameter(Mandatory=$false)] [array]$ScheduledTaskEvents,
        [Parameter(Mandatory=$false)] [int]$TimeWindowMinutes = 15
    )

    process {
        Write-Host "[*] Analyzing telemetry matrix for stateful persistence correlation chains..." -ForegroundColor Gray
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()
        $AtomicRegistryAlerts = [System.Collections.Generic.List[object]]::new()

        # ----------------------------------------------------------------------
        # STEP 1: Identify Host-Level Registry Footprints (Atomic Pass)
        # ----------------------------------------------------------------------
        if ($null -ne $RegistryEvents) {
            foreach ($Reg in $RegistryEvents) {
                if ($Reg.RegistryKey -like "*\CurrentVersion\Run*" -or $Reg.RegistryKey -like "*\CurrentVersion\*\Run*") {
                    
                    if ($Reg.NewValueData -like "*temp*" -or 
                        $Reg.NewValueData -like "*tmp*" -or 
                        $Reg.NewValueData -like "*svch0st*" -or 
                        $Reg.NewValueData -like "*cmd.exe*" -or 
                        $Reg.NewValueData -like "*powershell.exe*" -or 
                        $Reg.NewValueData -like "*iex*" -or 
                        $Reg.NewValueData -like "*certutil.exe*" -or 
                        $Reg.NewValueData -like "*MSHTA.exe*") {
                        
                        # Cache this as an indicator of compromise (IOC) to cross-correlate next
                        $AtomicRegistryAlerts.Add($Reg)
                    }
                }
            }
        }

        # ----------------------------------------------------------------------
        # STEP 2: Stateful Correlation Pass (Bridging Registry & Task Telemetry)
        # ----------------------------------------------------------------------
        if ($AtomicRegistryAlerts.Count -gt 0 -and $null -ne $ScheduledTaskEvents) {
            foreach ($RegAlert in $AtomicRegistryAlerts) {
                
                # Pivot Keys: Match target workstation/server AND user context
                $PivotComputer = $RegAlert.Computer
                $PivotUser     = $RegAlert.User
                $RegTime       = $RegAlert.TimeGenerated

                # Scan the task history list for records matching our pivot baseline
                foreach ($Task in $ScheduledTaskEvents) {
                    if ($Task.Computer -eq $PivotComputer -and $Task.User -eq $PivotUser) {
                        
                        # Apply Sliding Time Window constraint logic
                        $TimeDifference = [Math]::Abs(($Task.TimeGenerated - $RegTime).TotalMinutes)
                        
                        if ($TimeDifference -le $TimeWindowMinutes) {
                            
                            # Critical Correlation Confirmed: Attacker is compounding host holds
                            $DetectedThreats.Add([PSCustomObject]@{
                                Timestamp     = $Task.TimeGenerated
                                DetectionType = "Correlated Multi-Stage Persistence Footprint"
                                MITRE_ID      = "T1547.001 / T1053.005"
                                Severity      = "Critical"
                                Computer      = $PivotComputer
                                User          = $PivotUser
                                Description   = "CRITICAL ALERT: Correlated persistence maneuvers identified. A rogue startup Run configuration key was coupled with local Task Scheduler manipulation within a $TimeWindowMinutes-minute delta block."
                                Evidence      = @{
                                    CorrelationWindowMinutes = [Math]::Round($TimeDifference, 2)
                                    RegistryTrigger          = @{
                                        Key   = $RegAlert.RegistryKey
                                        Value = $RegAlert.ValueName
                                        Data  = $RegAlert.NewValueData
                                        Time  = $RegAlert.TimeGenerated
                                    }
                                    TaskSchedulerTrigger     = @{
                                        TaskName   = $Task.TaskName
                                        TaskPath   = $Task.TaskPath
                                        Activity   = $Task.Activity
                                        ActionName = $Task.ActionName
                                        Time       = $Task.TimeGenerated
                                    }
                                }
                            })
                        }
                    }
                }
            }
        }

        # Return consolidated stateful findings back to core engine output handler
        return $DetectedThreats
    }
}