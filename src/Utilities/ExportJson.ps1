# ==============================================================================
# Script: ThreatHunter-Detection-Platform - JSON Incident Export Utility
# Path:   src/Utils/ExportJson.ps1
# Description: Serializes customized incident objects into pristine JSON log files.
# ==============================================================================

function Export-IncidentJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [array]$AlertList,
        [Parameter(Mandatory=$true)] [string]$OutputDirectory,
        [Parameter(Mandatory=$false)] [string]$Depth=5
    )

    process {
        if ($AlertList.Count -eq 0) { return }

        # Ensure the destination output directory structure actually exists
        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
        }

        # Generate a clean timestamped filename to avoid resource naming collisions
        $Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $TargetFile = Join-Path $OutputDirectory "Alerts_$Timestamp.json"

        try {
            # Convert objects to deep structured JSON format (Depth 4 ensures evidence maps stay intact)
            $JsonPayload = $AlertList | ConvertTo-Json -Depth $Depth
            $JsonPayload | Out-File -FilePath $TargetFile -Encoding utf8
            
            Write-Host "[+] Successfully exported $($AlertList.Count) security alerts to JSON: $TargetFile" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to serialize alert array directly to JSON file: $_"
        }
    }
}