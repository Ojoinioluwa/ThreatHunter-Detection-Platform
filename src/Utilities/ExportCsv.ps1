# ==============================================================================
# Script: ThreatHunter-Detection-Platform - CSV Incident Export Utility
# Path:   src/Utils/ExportCsv.ps1
# Description: flattens custom objects to generate clean triage CSV lists.
# ==============================================================================

function Export-IncidentCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [array]$AlertList,
        [Parameter(Mandatory=$true)] [string]$OutputDirectory
    )

    process {
        if ($AlertList.Count -eq 0) { return }

        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
        }

        $Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $TargetFile = Join-Path $OutputDirectory "Alerts_$Timestamp.csv"

        try {
            # Flatten the rich nested Evidence hashtable into a simple string to keep the CSV clean
            $FlattenedAlerts = foreach ($Alert in $AlertList) {
                $EvidenceString = ""
                if ($null -ne $Alert.Evidence -and $Alert.Evidence -is [System.Collections.IDictionary]) {
                    # Convert key-value maps to a simple 'Key=Value; Key2=Value2' readable format
                    $EvidenceString = ($Alert.Evidence.Keys | ForEach-Object { "$_=$($Alert.Evidence[$_])" }) -join "; "
                } else {
                    $EvidenceString = $Alert.Evidence
                }

                [PSCustomObject]@{
                    Timestamp     = $Alert.Timestamp
                    DetectionType = $Alert.DetectionType
                    MITRE_ID      = $Alert.MITRE_ID
                    Severity      = $Alert.Severity
                    Computer      = $Alert.Computer
                    User          = $Alert.User
                    Description   = $Alert.Description
                    EvidenceSummary = $EvidenceString
                }
            }

            # Export data with standard fallback settings
            $FlattenedAlerts | Export-Csv -Path $TargetFile -NoTypeInformation -Encoding utf8
            Write-Host "[+] Successfully exported $($AlertList.Count) security alerts to CSV: $TargetFile" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to parse data matrix down to tabular CSV format: $_"
        }
    }
}