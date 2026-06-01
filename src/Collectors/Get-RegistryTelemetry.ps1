#######################################################################################
# Script: ThreatHunter-Detection-Platform - Registry Engine Collector
# Path:   src/Collectors/Get-RegistryTelemetry.ps1
# Description: Collects and normalizes Registry modification telemetries (EID 4657, 4656)
######################################################################################

$CoreDir = Join-Path $PSScriptRoot "../Core"
Import-Module (Join-Path $CoreDir "ConfigLoader.psm1") -Force
Import-Module (Join-Path $CoreDir "Logger.psm1") -Force
Import-Module (Join-Path $CoreDir "EventCollector.psm1") -Force

function Get-RegistryTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$LookbackHours=1,

        [Parameter(Mandatory=$false)]
        [string]$ConfigPath="../../config"
    )

    begin {
        Write-PlatformLog -Level "INFO" -Component "RegistryCollector" -Message "Initializing Registry Telemetry Cycle..."
        
        # Load configuration
        $ConfigRoot = Join-Path $PSScriptRoot $ConfigPath
        $Configs = Initialize-Config -ConfigRoot $ConfigRoot 

        # Gather target Registry IDs from configuration
        $UsedEventIds = $Configs.EventIDs.Registry.Values

        if ($null -eq $UsedEventIds -or $UsedEventIds.Count -eq 0) {
            Write-PlatformLog -Level "WARNING" -Component "RegistryCollector" -Message "Config mapping empty. Using default EIDs 4657, 4656."
            $UsedEventIds = @(4657, 4656)
        }
    }

    process {
        Write-PlatformLog -Level "INFO" -Component "RegistryCollector" -Message "Querying Security channel for Registry Event IDs: ($($UsedEventIds -join ', '))"
        $RawProcessLogs = Get-TelemetryBatch -LogName "Security" -EventIDs $UsedEventIds -WindowHours $LookbackHours
        
        $NormalizedEvents = [System.Collections.Generic.List[Object]]::new()
        
        foreach ($Log in $RawProcessLogs) {
            $XML = [xml]$Log.ToXml()
            
            $EventLogs = @{}
            foreach ($Data in $XML.Event.EventData.Data) {
                if ($null -ne $Data.Name) {
                    $EventLogs[$Data.Name] = $Data.'#text'
                }
            }

            $SystemNode = $XML.Event.System
            if ($null -ne $SystemNode) {
                $EventLogs["TimeCreated"] = $SystemNode.TimeCreated.SystemTime
                $EventLogs["ProcessId"]   = $SystemNode.Execution.ProcessID 
                $EventLogs["EventID"]     = [int]$SystemNode.EventID
                $EventLogs["Computer"]    = $SystemNode.Computer
                
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

            switch ($EventLogs["EventID"]) {
                4657 { # Registry Value Modified / Created / Deleted
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated = $EventLogs["TimeCreated"]
                        EventID       = 4657
                        Activity      = "Registry_Value_Changed"
                        User          = $EventLogs["OperatorUser"]
                        OperationType = $EventLogs["OperationType"] # Cleartext description of change
                        RegistryKey   = $EventLogs["ObjectName"]    # Full hive path
                        ValueName     = $EventLogs["ObjectValueName"] # The specific target key property name
                        NewValueData  = if ($EventLogs["NewValue"]) { $EventLogs["NewValue"].Trim() } else { "N/A / Deleted" }
                        OldValueData  = if ($EventLogs["OldValue"]) { $EventLogs["OldValue"].Trim() } else { "N/A" }
                        ProcessId     = $EventLogs["ProcessId"]
                        Computer      = $EventLogs["Computer"]
                    })
                }
                4656 { # Registry Key Handle Requested (Access auditing)
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated = $EventLogs["TimeCreated"]
                        EventID       = 4656
                        Activity      = "Registry_Handle_Requested"
                        User          = $EventLogs["OperatorUser"]
                        RegistryKey   = $EventLogs["ObjectName"]
                        ProcessId     = $EventLogs["ProcessId"]
                        Computer      = $EventLogs["Computer"]
                    })
                }
            }
        }
        
        Write-PlatformLog -Level "INFO" -Component "RegistryCollector" -Message "Successfully normalized $($NormalizedEvents.Count) registry telemetry records."
        Write-Output $NormalizedEvents
    }
    end {}
}