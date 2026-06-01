#######################################################################################
# Script: ThreatHunter-Detection-Platform - PowerShell Engine Collector
# Path: src/Collectors/Get-PowerShellTelemetry.ps1
# Description: Collects and normalizes deep-visibility Script Block logs (EID 4104)
######################################################################################

$CoreDir = Join-Path $PSScriptRoot "../Core"
Import-Module (Join-Path $CoreDir "ConfigLoader.psm1") -Force
Import-Module (Join-Path $CoreDir "Logger.psm1") -Force
Import-Module (Join-Path $CoreDir "EventCollector.psm1") -Force

function Get-PowerShellTelemetry { # Fixed spelling from Telementry
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$LookbackHours=1,

        [Parameter(Mandatory=$false)]
        [string]$ConfigPath="../../config"
    )

    begin {
        # Write-PlatformLog -Level "INFO" -Component "PowershellCollector" -Message "Initializing PowerShell Telemetry Cycle..."
        
        # Load configuration
        $ConfigRoot = Join-Path $PSScriptRoot $ConfigPath
        $Configs = Initialize-Config -ConfigRoot $ConfigRoot 

        # Get the event id from the configuration
        $UsedEventIds = $Configs.EventIDs.PowershellExec.Values

        # FIX 1: Fixed spelling mismatch from $UsedEventId to $UsedEventIds
        if ($null -eq $UsedEventIds -or $UsedEventIds.Count -eq 0) {
            Write-PlatformLog -Level "WARNING" -Component "PowershellCollector" -Message "Config mapping empty. Using default EIDs 4104."
            $UsedEventIds = @(4104)
        }
    }

    process {
        $RawProcessLogs = Get-TelemetryBatch -LogName "Microsoft-Windows-PowerShell/Operational" -EventIDs $UsedEventIds -WindowHours $LookbackHours
        
        $NormalizedEvents = [System.Collections.Generic.List[Object]]::new()
        
        foreach ($Log in $RawProcessLogs) {

            $XML = [xml]$Log.ToXml()
            
            # $XML.OuterXml | Out-File -FilePath "C:\Users\Inioluwa\Documents\Coding_projects\ThreatHunter-Detection-Platform\src\Collectors\jj.xml" -Append -Force

            # lookup data map for this event entry
            $EventLogs = @{}
            
            # Map EventData node tags
            foreach ($Data in $XML.Event.EventData.Data) {
                if ($null -ne $Data.Name) {
                    $EventLogs[$Data.Name] = $Data.'#text'
                }
            }

            # FIX 2 & 3: Direct mapping of System data fields without loop structure, matching XML schema casing
            $SystemNode = $XML.Event.System
            if ($null -ne $SystemNode) {
                $EventLogs["TimeCreated"] = $SystemNode.TimeCreated.SystemTime
                $EventLogs["ProcessId"]   = $SystemNode.Execution.ProcessID # Schema matches uppercase ID
                
                $AddedUserValue = $SystemNode.Security.UserID # Schema matches uppercase ID
                if ($AddedUserValue -like "S-1-5-*") {
                    try {
                        $Identifier = [System.Security.Principal.SecurityIdentifier]::new($AddedUserValue)
                        $AddedUserName = $Identifier.Translate([System.Security.Principal.NTAccount]).Value.Split("\")[-1]
                        $EventLogs["TargetUser"] = $AddedUserName
                    } catch {
                        $EventLogs["TargetUser"] = $AddedUserValue # Fallback to raw SID string if lookup fails
                    }
                } else {
                    $EventLogs["TargetUser"] = $AddedUserValue
                }
            }

            if ($Log.Id -eq 4104) {
                # Safeguard against missing script path attributes
                $ExecPath = if (-not [string]::IsNullOrWhiteSpace($EventLogs["Path"])) { $EventLogs["Path"] } else { "Interactive Console / Direct Input" }
                
                $NormalizedEvents.Add([PSCustomObject]@{
                    TimeGenerated = $EventLogs["TimeCreated"]
                    EventID       = 4104
                    Activity      = "Script_Block_Execution"
                    User          = $EventLogs["TargetUser"]
                    ScriptBlockID = $EventLogs["ScriptBlockId"]
                    ExecutionPath = $ExecPath  
                    ScriptContent = if ($EventLogs["ScriptBlockText"]) { $EventLogs["ScriptBlockText"].Trim() } else { $null }
                    ProcessId     = $EventLogs["ProcessId"]
                })
            }
        }

        
        # Write-PlatformLog -Level "INFO" -Component "PowershellCollector" -Message "Successfully normalized $($NormalizedEvents.Count) process telemetry records."
        
        return $NormalizedEvents
    }
    end {}
}