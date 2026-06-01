# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Process Creation Collector
# Path:   src/Collectors/Get-ProcessTelemetry.ps1
# Description: Collects, extracts, and normalizes Process telemetry via XML parsing.
# ==============================================================================

# 1. Import Platform Core Infrastructure Anchors
$CoreDir = Join-Path $PSScriptRoot "../Core"
Import-Module (Join-Path $CoreDir "EventCollector.psm1") -Force
Import-Module (Join-Path $CoreDir "Logger.psm1") -Force
Import-Module (Join-Path $CoreDir "ConfigLoader.psm1") -Force

function Get-ProcessTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$LookbackHours = 1,

        [Parameter(Mandatory = $false)]
        [string]$ConfigPath = "../../config"
    )

    begin {
        Write-PlatformLog -Level "INFO" -Component "ProcessCollector" -Message "Initializing Process Telemetry collection cycle..."

        # Load configurations dynamically
        $ConfigRoot = Join-Path $PSScriptRoot $ConfigPath
        $Configs = Initialize-Config -ConfigRoot $ConfigRoot
        
        # Pull target IDs from the class configuration mappings
        $UsedEventIds = $Configs.EventIDs.ProcessExecution.Values
        
        # Fallback safeguard check if config isn't initialized or empty
        if ($null -eq $UsedEventIds -or $UsedEventIds.Count -eq 0) {
            Write-PlatformLog -Level "WARNING" -Component "ProcessCollector" -Message "Config mapping empty. Using default EIDs 4688 and 4689."
            $UsedEventIds = @(4688, 4689)
        }
    }

    process {
        Write-PlatformLog -Level "INFO" -Component "ProcessCollector" -Message "Querying Security log channel for Event IDs: ($($UsedEventIds -join ', ')) over last $LookbackHours hour(s)."
        
        # Call your core ingestion module
        $RawProcessLogs = Get-TelemetryBatch -LogName "Security" -EventIDs $UsedEventIds -WindowHours $LookbackHours

        if ($null -eq $RawProcessLogs -or $RawProcessLogs.Count -eq 0) {
            Write-PlatformLog -Level "INFO" -Component "ProcessCollector" -Message "No process creation or termination events found within lookback window."
            return
        }

        $NormalizedEvents = [System.Collections.Generic.List[object]]::new()

        foreach ($Log in $RawProcessLogs) {
            # Convert raw log data to structured XML object safely
            $Xml = [xml]$Log.ToXml()
            
            # Map dynamic XML schema fields to a clean key-value hashtable
            $EventData = @{}
            foreach ($Data in $Xml.Event.EventData.Data) {
                if ($null -ne $Data.Name) {
                    $EventData[$Data.Name] = $Data.'#text'
                }
            }

            # Branch evaluation based on event type
            if ($Log.Id -eq 4688) {
                $FullPath      = $EventData["NewProcessName"]
                $CommandLine   = $EventData["CommandLine"]
                $ParentProcess = $EventData["ParentProcessName"]
                $AccountName   = $EventData["TargetUserName"]

                $ProcessExecutable = if ($FullPath) { Split-Path $FullPath -Leaf } else { "Unknown" }

                $NormalizedEvents.Add([PSCustomObject]@{
                    TimeGenerated = $Log.TimeCreated
                    EventID       = 4688
                    Activity      = "Process_Creation"
                    User          = $AccountName
                    ProcessName   = $ProcessExecutable
                    FullPath      = $FullPath
                    CommandLine   = if ($CommandLine) { $CommandLine } else { "Not Enabled/Empty" }
                    ParentProcess = $ParentProcess
                })

            } elseif ($Log.Id -eq 4689) {
                $FullPath    = $EventData["ProcessName"]
                $AccountName = $EventData["TargetUserName"]
                
                $ProcessExecutable = if ($FullPath) { Split-Path $FullPath -Leaf } else { "Unknown" }

                $NormalizedEvents.Add([PSCustomObject]@{
                    TimeGenerated = $Log.TimeCreated
                    EventID       = 4689
                    Activity      = "Process_Termination"
                    User          = $AccountName
                    ProcessName   = $ProcessExecutable
                    FullPath      = $FullPath
                    CommandLine   = "N/A - Termination"
                    ParentProcess = "N/A - Termination"
                })
            }
        }

        Write-PlatformLog -Level "INFO" -Component "ProcessCollector" -Message "Successfully normalized $($NormalizedEvents.Count) process telemetry records."
        
        # Emit objects down the pipeline stream
        Write-Output $NormalizedEvents
    }

    end {}
}



