




# #################
# Still need to update this to contain more timelines
################


function New-AttackTimeline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents,
        
        [Parameter(Mandatory=$false)]
        [string]$TargetComputer = "DESKTOP-UTI6F75"
    )

    process {
        # 1. Gather telemetry from all sources and sort strictly by time
        $Timeline = $AllNormalizedEvents | 
            Where-Object { $_.Computer -eq $TargetComputer } | 
            Sort-Object TimeGenerated

        $StoryBoard = [System.Collections.Generic.List[object]]::new()

        # 2. Step through the timeline to look for cross-log relationships
        foreach ($Event in $Timeline) {
            
            # If a process created a known persistence mechanism, map it!
            if ($Event.Activity -eq "Registry_Value_Changed" -and $Event.RegistryKey -like "*CurrentVersion\Run*") {
                $StoryBoard.Add([PSCustomObject]@{
                    Timestamp = $Event.TimeGenerated
                    Phase     = "Persistence (TA0003)"
                    Summary   = "User [$($Event.User)] modified Run Key [$($Event.ValueName)] to execute payload."
                    Data      = $Event.NewValueData
                })
            }

            # If a suspicious scheduled task executed immediately after
            if ($Event.Activity -eq "Scheduled_Task_Executed") {
                $StoryBoard.Add([PSCustomObject]@{
                    Timestamp = $Event.TimeGenerated
                    Phase     = "Execution (TA0002)"
                    Summary   = "Scheduled Task [$($Event.TaskName)] fired, spawning: $($Event.ActionName)"
                    Data      = $Event.ActionName
                })
            }
        }

        return $StoryBoard
    }
}