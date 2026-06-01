# ==============================================================================
# Script: ThreatHunter-Detection-Platform - Platform Bootstrapper
# Path:   scripts/Start-Monitoring.ps1
# Description: Instantiates the detection engine and runs the continuous telemetry loop.
# ==============================================================================
using module "..\src\Core\DetectionEngine.psm1"

# 1. PARAMETER LAYER: Allows the user to select the collector function dynamically
param(
    [Parameter(Mandatory = $true, HelpMessage = "Provide the target ingestion collector function name (e.g., Get-PowerShellTelemetry, Get-ProcessTelemetry, Get-RegistryTelemetry, Get-ScheduledTaskTelemetry, Get-SecurityTelemetry, Get-SyntheticTelemetry)")]
    [ValidateSet("Get-PowerShellTelemetry", "Get-ProcessTelemetry", "Get-RegistryTelemetry", "Get-ScheduledTaskTelemetry", "Get-SecurityTelemetry", "Get-SyntheticTelemetry")]
    [ValidateNotNullOrEmpty()]
    [string]$CollectorFunction,
    [Parameter(Mandatory=$false)]
    [int]$LookbackHours=2

)

# 2. CRITICAL: Compiler Type Binding

Clear-Host
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "         THREATHUNTER DETECTION PLATFORM - ORCHESTRATION LAYER         " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 3. Environment Path Resolving
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$ConfigPath  = Join-Path $ProjectRoot "config"

# Import our collectors and export utilities cleanly
. (Join-Path $ProjectRoot "scripts/Run-Simulation.ps1")

# Initialize local array containers to track file basename1s
$DetectionsRoster  = @()
$CorrelatorsRoster = @()

# Dynamic Search & Compilation Pass
$DetectionsDirectory  = Join-Path $ProjectRoot "src/Detections"
$CorrelationDirectory = Join-Path $ProjectRoot "src/Correlation"
$UtilitiesDirectory   = Join-Path $ProjectRoot "src/Utilities"
$CollectorsDirectory  = Join-Path $ProjectRoot "src/Collectors"

# Load Utilities & Collectors first so they are available immediately
Get-ChildItem -Path $UtilitiesDirectory -Filter "*.ps1" -Recurse | ForEach-Object { . $_.FullName }
Get-ChildItem -Path $CollectorsDirectory -Filter "*.ps1" -Recurse | ForEach-Object { . $_.FullName }
Get-ChildItem -Path $DetectionsDirectory -Filter "*.ps1" -Recurse | ForEach-Object { . $_.FullName }

# 4. RUNTIME ACCREDITATION: Verify that the user's requested collector exists in memory
if (-not (Get-Command $CollectorFunction -ErrorAction SilentlyContinue)) {
    Write-Error "The requested collector function '$CollectorFunction' was not found in memory. Please check your spelling or verify your collector scripts exist."
    Exit
} else {
    Write-Host "[+] Confirmed runtime collection engine targeted: $CollectorFunction" -ForegroundColor Green
}

# Scan, Dot-Source, and Catalog Stateless Rules
if (Test-Path $DetectionsDirectory) {
    Get-ChildItem -Path $DetectionsDirectory -Filter "*.ps1" -Recurse | ForEach-Object {
        . $_.FullName
        $DetectionsRoster += $_.BaseName
        Write-Host "    -> Imported & Registered Rule: $($_.BaseName)" -ForegroundColor DarkGray
    }
}

# Scan, Dot-Source, and Catalog Stateful Correlators
if (Test-Path $CorrelationDirectory) {
    Get-ChildItem -Path $CorrelationDirectory -Filter "*.ps1" -Recurse | ForEach-Object {
        . $_.FullName
        $CorrelatorsRoster += $_.BaseName
        Write-Host "    -> Imported & Registered Correlator: $($_.BaseName)" -ForegroundColor DarkGray
    }
}

# 5. Read Central Configuration Settings
$PlatformConfig = Get-Content -Path (Join-Path $ConfigPath "detectionconfig.json") | ConvertFrom-Json

# 6. Instantiate the Engine Class Object
$Engine = [DetectionEngine]::new($ConfigPath, $PlatformConfig.OutputDirectory)
$Engine.InitializePlatform()

Write-Host "`n[+] ThreatHunter Platform Engine is live and actively hunting..." -ForegroundColor Green
Write-Host "[*] Ingestion Source Strategy: $CollectorFunction" -ForegroundColor Yellow
Write-Host "[*] Press [CTRL+C] to stop monitoring.`n" -ForegroundColor Yellow

# 7. The Main Event Polling Loop
$Running = $true
while ($Running) {
    try {
        Write-Host "[*] Ingesting telemetry slice via $CollectorFunction... $((Get-Date).ToString('HH:mm:ss'))" -ForegroundColor DarkGray
        
        # 💡 DYNAMIC INVOCATION: Calls whatever function name was passed to the param block
        $RawEvents = & $CollectorFunction -LookbackHours $LookbackHours
        
        $RawEvents | ConvertTo-Json -Depth 5 | Out-File -FilePath "$ConfigPath\Ini.json" 

        # Route Telemetry to Engine Parsing Matrix
        if ($null -ne $RawEvents -and $RawEvents.Count -gt 0) {
            Write-Host "[!] Passing $($RawEvents.Count) items to engine..." -ForegroundColor Cyan
            
            # Run the analytics pass
            $AlertsGenerated = $Engine.ProcessBatch($RawEvents)

            # --- Step C: Export Identified Threat Anomalies ---
            if ($null -ne $AlertsGenerated -and $AlertsGenerated.Count -gt 0) {
                Write-Host "[ALERT] -> Detected $($AlertsGenerated.Count) active security threats!" -ForegroundColor Red
                Export-IncidentJson -AlertList $AlertsGenerated -OutputDirectory $PlatformConfig.OutputDirectory -Depth 10
            } else {
                Write-Host "[*] Engine scan complete. The data evaluated clean against all active rules." -ForegroundColor Gray
            }
        } else {
            Write-Host "[-] Collector run returned 0 events. Checking pipeline timeline parameters..." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Critical error in orchestrator processing loop: $_"
    }

    # Rest the process according to configured cycle specifications
    Start-Sleep -Seconds $PlatformConfig.PollingIntervalSeconds
}