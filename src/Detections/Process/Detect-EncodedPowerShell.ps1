# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Encoded PowerShell Session Detector
# Path:   src/Detection/Process/Detect-EncodedPowerShell.ps1
# Description: Flags encoded execution arguments and automatically extracts payloads.
# ==============================================================================

function Detect-EncodedPowerShell {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        foreach ($Proc in $NormalizedSecurityEvents) {
            # Isolate PowerShell / pwsh instances
            if ($Proc.ProcessName -like "*powershell.exe*" -or $Proc.ProcessName -like "*pwsh.exe*") {
                $CmdLine = $Proc.CommandLine

                if (-not [string]::IsNullOrWhiteSpace($CmdLine)) {
                    # IMPROVED REGEX: Matches both dashes and forward slashes, optional leading space,
                    # and case-insensitive variations of -e, -enc, -encoded, -encodedcommand
                    if ($CmdLine -match "(?i)(?:\s+|^)[-/](e|enc|encoded|encodedcommand)\s+([A-Za-z0-9+/=]+)") {
                        
                        $Base64Payload = $Matches[2].Trim()
                        $DecodedPayload = "UNABLE_TO_DECODE"

                        try {
                            # Convert the raw extracted string directly to byte structures
                            $Bytes = [System.Convert]::FromBase64String($Base64Payload)
                            
                            # Standard Windows PowerShell EncodedCommand strings utilize UTF-16LE
                            $DecodedPayload = [System.Text.Encoding]::Unicode.GetString($Bytes)
                        } 
                        catch {
                            # Fallback alignment verification pass
                            try {
                                if ($null -ne $Bytes) {
                                    $DecodedPayload = [System.Text.Encoding]::UTF8.GetString($Bytes)
                                }
                            } 
                            catch { 
                                $DecodedPayload = "DECODE_ERROR: $($_.Exception.Message)"
                            }
                        }

                        # Construct clean Alert Object (The Engine handles injecting severity scoring updates dynamically)
                        $DetectedThreats.Add([PSCustomObject]@{
                            Timestamp     = $Proc.TimeGenerated
                            DetectionType = "Obfuscated PowerShell Execution"
                            MITRE_ID      = "T1027"       # Obfuscated Files or Information
                            Severity      = "Critical"    # Default high-priority validation signature
                            Computer      = $Proc.Computer
                            User          = $Proc.User
                            Description   = "An obfuscated base64 PowerShell execution sequence was identified and automatically decoded by the platform."
                            Evidence      = @{
                                ProcessName     = $Proc.ProcessName
                                RawCommandLine  = $CmdLine
                                ExtractedBase64 = $Base64Payload
                                DecodedCommand  = $DecodedPayload.Trim()
                                ParentProcess   = $Proc.ParentProcessName
                            }
                        })
                    }
                }
            }
        }

        return $DetectedThreats
    }
}