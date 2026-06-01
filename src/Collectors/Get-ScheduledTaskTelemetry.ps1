#######################################################################################
# Script: ThreatHunter-Detection-Platform - ScheduledTask Engine Collector
# Path:   src/Collectors/Get-ScheduledTaskTelemetry.ps1
# Description: Collects and normalizes Scheduled Task lifecycle events (EID 106, 140, 141, 200)
######################################################################################

$CoreDir = Join-Path $PSScriptRoot "../Core"
Import-Module (Join-Path $CoreDir "ConfigLoader.psm1") -Force
Import-Module (Join-Path $CoreDir "Logger.psm1") -Force
Import-Module (Join-Path $CoreDir "EventCollector.psm1") -Force

function Get-ScheduledTaskTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$LookbackHours=1,

        [Parameter(Mandatory=$false)]
        [string]$ConfigPath="../../config"
    )

    begin {
        Write-PlatformLog -Level "INFO" -Component "ScheduledTaskCollector" -Message "Initializing Scheduled Task Telemetry Cycle..."
        
        # Load configuration
        $ConfigRoot = Join-Path $PSScriptRoot $ConfigPath
        $Configs = Initialize-Config -ConfigRoot $ConfigRoot 

        # Get the event ids from the configuration
        $UsedEventIds = $Configs.EventIDs.ScheduledTask.Values

        if ($null -eq $UsedEventIds -or $UsedEventIds.Count -eq 0) {
            Write-PlatformLog -Level "WARNING" -Component "ScheduledTaskCollector" -Message "Config mapping empty. Using default EIDs 106, 140, 141, 200."
            $UsedEventIds = @(106, 140, 141, 200)
        }
    }

    process {
        Write-PlatformLog -Level "INFO" -Component "ScheduledTaskCollector" -Message "Querying TaskScheduler provider for Event IDs: ($($UsedEventIds -join ', '))"
        $RawProcessLogs = Get-TelemetryBatch -LogName "Microsoft-Windows-TaskScheduler/Operational" -EventIDs $UsedEventIds -WindowHours $LookbackHours
        
        $NormalizedEvents = [System.Collections.Generic.List[Object]]::new()
        
        foreach ($Log in $RawProcessLogs) {
            $XML = [xml]$Log.ToXml()
            
            # Dynamic key-value lookup map for Task Engine EventData
            $EventLogs = @{}
            foreach ($Data in $XML.Event.EventData.Data) {
                if ($null -ne $Data.Name) {
                    $EventLogs[$Data.Name] = $Data.'#text'
                }
            }

            # Map standard System properties
            $SystemNode = $XML.Event.System
            if ($null -ne $SystemNode) {
                $EventLogs["TimeCreated"] = $SystemNode.TimeCreated.SystemTime
                $EventLogs["ProcessId"]   = $SystemNode.Execution.ProcessID 
                $EventLogs["EventID"]     = [int]$SystemNode.EventID
                $EventLogs["Computer"]    = $SystemNode.Computer
                
                # Resolve User Context who manipulated/ran the task from the Security Context SID
                $AddedUserValue = $SystemNode.Security.UserID
                if ($AddedUserValue -like "S-1-5-*") {
                    try {
                        $Identifier = [System.Security.Principal.SecurityIdentifier]::new($AddedUserValue)
                        $EventLogs["OperatorUser"] = $Identifier.Translate([System.Security.Principal.NTAccount]).Value.Split("\")[-1]
                    } catch {
                        $EventLogs["OperatorUser"] = $AddedUserValue
                    }
                } else {
                    $EventLogs["OperatorUser"] = $AddedUserValue
                }
            }

            # Route normalization mappings based on the task action schema rules
            switch ($EventLogs["EventID"]) {
                106 { # Task Registered / Created
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated = $EventLogs["TimeCreated"]
                        EventID       = 106
                        Activity      = "Scheduled_Task_Created"
                        User          = $EventLogs["OperatorUser"]
                        TaskName      = $EventLogs["TaskName"]
                        TaskPath      = $EventLogs["Path"]
                        Computer      = $EventLogs["Computer"]
                        ProcessId     = $EventLogs["ProcessId"]
                    })
                }
                140 { # Task Updated / Modified
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated = $EventLogs["TimeCreated"]
                        EventID       = 140
                        Activity      = "Scheduled_Task_Modified"
                        User          = $EventLogs["OperatorUser"]
                        TaskName      = $EventLogs["TaskName"]
                        TaskPath      = $EventLogs["Path"]
                        Computer      = $EventLogs["Computer"]
                        ProcessId     = $EventLogs["ProcessId"]
                    })
                }
                141 { # Task Deleted
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated = $EventLogs["TimeCreated"]
                        EventID       = 141
                        Activity      = "Scheduled_Task_Deleted"
                        User          = $EventLogs["OperatorUser"]
                        TaskName      = $EventLogs["TaskName"]
                        TaskPath      = $EventLogs["Path"]
                        Computer      = $EventLogs["Computer"]
                        ProcessId     = $EventLogs["ProcessId"]
                    })
                }
                200 { # Task Executed / Started
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated = $EventLogs["TimeCreated"]
                        EventID       = 200
                        Activity      = "Scheduled_Task_Executed"
                        User          = $EventLogs["OperatorUser"]
                        TaskName      = $EventLogs["TaskName"]
                        TaskPath      = $EventLogs["Path"]
                        ActionName    = $EventLogs["ActionName"] # Captures the binary/script launched by the task!
                        Computer      = $EventLogs["Computer"]
                        ProcessId     = $EventLogs["ProcessId"]
                    })
                }
            }
        }
        
        Write-PlatformLog -Level "INFO" -Component "ScheduledTaskCollector" -Message "Successfully normalized $($NormalizedEvents.Count) scheduled task records."
        Write-Output $NormalizedEvents
    }
    end {}
}