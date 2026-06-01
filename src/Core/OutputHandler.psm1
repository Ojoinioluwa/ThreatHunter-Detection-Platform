# ==============================================================================
# Module: ThreatHunter-Detection-Platform - Output Handler
# Path:   src/Core/OutputHandler.psm1
# Description: Normalizes, serializes, and routes security alerts to storage.
# ==============================================================================

function Out-PlatformAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$Alert,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    begin {
        # Ensure target logging directory exists on the system filesystem
        $TargetDir = Split-Path $OutputFile -Parent
        if (-not (Test-Path $TargetDir)) {
            New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
        }
    }

    process {
        foreach ($SingleAlert in $Alert) {
            # 1. Normalization Layer: Enrich alert with uniform platform fields
            $NormalizedAlert = [ordered]@{
                AlertID       = [guid]::NewGuid().ToString()
                Timestamp     = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
                HostMachine   = $env:COMPUTERNAME
                TelemetryData = $SingleAlert
            }

            $AlertObject = [PSCustomObject]$NormalizedAlert

            # 2. Console Output Stream (For local terminal visibility / debugging)
            $HostColor = if ($SingleAlert.Severity -eq "High" -or $SingleAlert.Severity) { "Red" } else { "Yellow" }
            Write-Host "[!] SECURITY ALERT [Severity: $($SingleAlert.Severity)] - $($SingleAlert.DetectionType)" -ForegroundColor $HostColor
            
            # 3. File Persistence Layer: Append to JSON alert transaction ledger
            # We convert to JSON single-line format for easy streaming log processing (NDJSON format)
            $JsonPayload = $AlertObject | ConvertTo-Json -Depth 5 -Compress
            Add-Content -Path $OutputFile -Value $JsonPayload
            
            # Emit the normalized object down the pipeline if needed for secondary tasks
            Write-Output $AlertObject
        }
    }

    end {}
}

Export-ModuleMember -Function Out-PlatformAlert