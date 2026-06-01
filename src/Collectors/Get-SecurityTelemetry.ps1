#######################################################################################
# Script: ThreatHunter-Detection-Platform - Security Infrastructure Collector
# Path:   src/Collectors/Get-SecurityTelemetry.ps1
# Description: Collects and normalizes Core Security Logs (Auth, Account Mgmt, Defense Evasion)
######################################################################################

$CoreDir = Join-Path $PSScriptRoot "../Core"
Import-Module (Join-Path $CoreDir "ConfigLoader.psm1") -Force
Import-Module (Join-Path $CoreDir "Logger.psm1") -Force
Import-Module (Join-Path $CoreDir "EventCollector.psm1") -Force

function Get-SecurityTelemetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [int]$LookbackHours=1,

        [Parameter(Mandatory=$false)]
        [string]$ConfigPath="../../config"
    )

    begin {
        Write-PlatformLog -Level "INFO" -Component "SecurityCollector" -Message "Initializing Security Infrastructure Telemetry Cycle..."
        
        # Load configuration
        $ConfigRoot = Join-Path $PSScriptRoot $ConfigPath
        $Configs = Initialize-Config -ConfigRoot $ConfigRoot 

        # Gather and merge relevant Event IDs safely
        $RawIds = @()
        if ($null -ne $Configs.EventIDs.Authentication) { $RawIds += $Configs.EventIDs.Authentication.Values }
        if ($null -ne $Configs.EventIDs.AccountManagement) { $RawIds += $Configs.EventIDs.AccountManagement.Values }
        if ($null -ne $Configs.EventIDs.DefenseEvasion) { $RawIds += $Configs.EventIDs.DefenseEvasion.Values }

        [int[]]$UsedEventIds = $RawIds | Select-Object -Unique
        
        if ($null -eq $UsedEventIds -or $UsedEventIds.Count -eq 0) {
            Write-PlatformLog -Level "WARNING" -Component "SecurityCollector" -Message "Config mapping empty. Using default Infrastructure EIDs."
            $UsedEventIds = @(4624, 4625, 4720, 4726, 4732, 4728, 1102, 4724)
        }
    }

    process {
        Write-PlatformLog -Level "INFO" -Component "SecurityCollector" -Message "Querying Security log channel for Event IDs: ($($UsedEventIds -join ', '))"
        $RawProcessLogs = Get-TelemetryBatch -LogName "Security" -EventIDs $UsedEventIds -WindowHours $LookbackHours
        
        $NormalizedEvents = [System.Collections.Generic.List[Object]]::new()
        
        foreach ($Log in $RawProcessLogs) {
            $XML = [xml]$Log.ToXml()

            # Dynamic key-value lookup map for EventData
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
                
                # Resolve User Context from SID
                $AddedUserValue = $SystemNode.Security.UserID
                if ($AddedUserValue -like "S-1-5-*") {
                    try {
                        $Identifier = [System.Security.Principal.SecurityIdentifier]::new($AddedUserValue)
                        $EventLogs["TargetUser"] = $Identifier.Translate([System.Security.Principal.NTAccount]).Value.Split("\")[-1]
                    } catch {
                        $EventLogs["TargetUser"] = $AddedUserValue
                    }
                } else {
                    $EventLogs["TargetUser"] = $AddedUserValue
                }
            }

            switch ($EventLogs["EventID"]) {
                { $_ -eq 4624 -or $_ -eq 4625 } {
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated     = $EventLogs["TimeCreated"]
                        EventID           = $EventLogs["EventID"]
                        Activity          = if ($EventLogs["EventID"] -eq 4624) { "Logon_Success" } else { "Logon_Failure" }
                        User              = if ($EventLogs["TargetUserName"]) { $EventLogs["TargetUserName"] } else { $EventLogs["TargetUser"] }
                        ProcessId         = $EventLogs["ProcessId"]
                        ProcessName       = $EventLogs["ProcessName"]
                        IpAddress         = $EventLogs["IpAddress"]
                        TargetDomainName  = $EventLogs["TargetDomainName"]
                        SubjectUserName   = $EventLogs["SubjectUserName"]
                        SubjectDomainName = $EventLogs["SubjectDomainName"]
                        SubjectLogonId    = $EventLogs["SubjectLogonId"]
                        IpPort            = $EventLogs["IpPort"]
                        LogonType         = $EventLogs["LogonType"]
                        LogonProcessName  = $EventLogs["LogonProcessName"]
                        Computer          = $EventLogs["Computer"]
                    })
                }

                # --- SCOPE 2: ACCOUNT MANAGEMENT ---
                { $_ -eq 4720 -or 
                    $_ -eq 4726 -or 
                    $_ -eq 4732 -or 
                    $_ -eq 4728 -or 
                    $_ -eq 4728  -or 
                    $_ -eq 4724 
                } {
                    $ActivityString = switch ($EventLogs["EventID"]) {
                        4720 { "User_Account_Created" }
                        4726 { "User_Account_Deleted" }
                        4724 { "Password_reset" }
                        4732 { "Local_Group_Member_Added" }
                        4728 { "Global_Group_Member_Added" }
                    }

                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated     = $EventLogs["TimeCreated"]
                        EventID           = $EventLogs["EventID"]
                        Activity          = $ActivityString
                        User              = $EventLogs["TargetUserName"] 
                        TargetSid         = $EventLogs["TargetSid"]
                        GroupName         = $EventLogs["TargetGroupName"] 
                        SubjectUserName   = $EventLogs["SubjectUserName"] 
                        SubjectDomainName = $EventLogs["SubjectDomainName"]
                        SubjectLogonId    = $EventLogs["SubjectLogonId"]
                        Computer          = $EventLogs["Computer"]
                        ProcessId         = $EventLogs["ProcessId"]
                    })
                }

                1102 {
                    $NormalizedEvents.Add([PSCustomObject]@{
                        TimeGenerated     = $EventLogs["TimeCreated"]
                        EventID           = 1102
                        Activity          = "Security_Audit_Log_Cleared"
                        User              = $EventLogs["TargetUser"] 
                        SubjectUserName   = $EventLogs["SubjectUserName"]
                        SubjectDomainName = $EventLogs["SubjectDomainName"]
                        SubjectLogonId    = $EventLogs["SubjectLogonId"]
                        Computer          = $EventLogs["Computer"]
                        ProcessId         = $EventLogs["ProcessId"]
                    })
                }
            }
        }

        Write-PlatformLog -Level "INFO" -Component "SecurityCollector" -Message "Successfully normalized $($NormalizedEvents.Count) infrastructure security records."
        Write-Output $NormalizedEvents
    }
    end {}
}