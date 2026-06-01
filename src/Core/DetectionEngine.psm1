# ==============================================================================
# Module: ThreatHunter-Detection-Platform - Core Detection Engine
# Path:   src/Core/DetectionEngine.psm1
# Description: Central orchestrator coordinating log ingestion, signature evaluation,
#              cross-layer correlation, and output handling.
# ==============================================================================

class DetectionEngine {
    [string]$ConfigPath
    [string]$OutputPath
    [array]$LoadedDetections
    [array]$LoadedCorrelators

    DetectionEngine([string]$configPath, [string]$outputPath) {
        $this.ConfigPath = $configPath
        $this.OutputPath = $outputPath
        $this.LoadedDetections = @()
        $this.LoadedCorrelators = @()
    }

    # 1. Dynamically discover and catalog all rules inside our detection matrices
    [void] InitializePlatform() {
        Write-Host "[*] Initializing ThreatHunter Core Orchestration Engine..." -ForegroundColor Cyan
        
        $DetectionsDirectory  = Join-Path $PSScriptRoot "../Detections"
        $CorrelationDirectory = Join-Path $PSScriptRoot "../Correlation"

        # Catalog all stateless detection rules
        if (Test-Path $DetectionsDirectory) {
            $DetectionFiles = Get-ChildItem -Path $DetectionsDirectory -Filter "*.ps1" -Recurse
            foreach ($File in $DetectionFiles) {
                $this.LoadedDetections += $File.BaseName
                Write-Host "    -> Registered Stateless Rule: $($File.BaseName)" -ForegroundColor DarkGray
            }
        }

        # Catalog all stateful correlation models
        if (Test-Path $CorrelationDirectory) {
            $CorrelationFiles = Get-ChildItem -Path $CorrelationDirectory -Filter "*.ps1" -Recurse
            foreach ($File in $CorrelationFiles) {
                $this.LoadedCorrelators += $File.BaseName
                Write-Host "    -> Registered Stateful Correlator: $($File.BaseName)" -ForegroundColor DarkGray
            }
        }

        Write-Host "[+] Platform engine ready. Total Modules Registered: $($this.LoadedDetections.Count + $this.LoadedCorrelators.Count)" -ForegroundColor Green
    }

    # 2. Main processing loop that receives telemetry batches and executes inspection passes
    [array] ProcessBatch([array]$NormalizedEvents) {
        if ($null -eq $NormalizedEvents -or $NormalizedEvents.Count -eq 0) {
            Write-Host "[-] ProcessBatch received empty telemetry data. Skipping evaluation cycle." -ForegroundColor DarkYellow
            return @()
        }

        $DetectedAlerts = [System.Collections.Generic.List[object]]::new()

        Write-Host "`n--- [START PIPELINE EVALUATION: $($NormalizedEvents.Count) EVENTS] ---" -ForegroundColor Gray

        # --- Phase A: Execute Stateless Signature Detection Layers ---
        foreach ($RuleName in $this.LoadedDetections) {
            try {
                if (Get-Command $RuleName -ErrorAction SilentlyContinue) {
                    Write-Host "[EVALUATING] -> Running rule: $RuleName" -ForegroundColor Cyan
                    
                    # Execute function dynamically via its cataloged name string
                    $RuleAlerts = & $RuleName -NormalizedSecurityEvents $NormalizedEvents
                    
                    if ($null -ne $RuleAlerts -and $RuleAlerts.Count -gt 0) {
                        Write-Host "   [MATCH] -> $RuleName triggered $($RuleAlerts.Count) alert(s)!" -ForegroundColor Red
                        foreach ($Alert in $RuleAlerts) { [void]$DetectedAlerts.Add($Alert) }
                    } else {
                        Write-Host "   [CLEAN] -> $RuleName evaluated data. No matches found." -ForegroundColor DarkGreen
                    }
                } else {
                    Write-Host "[WARNING] -> Registered rule '$RuleName' was not found in session memory! Verify function naming." -ForegroundColor Yellow
                }
            } catch {
                Write-Error "Execution breakdown inside stateless signature module [$RuleName]: $_"
            }
        }

        # --- Phase B: Execute Stateful Complex Correlation Layers ---
        foreach ($CorrelatorName in $this.LoadedCorrelators) {
            try {
                if (Get-Command $CorrelatorName -ErrorAction SilentlyContinue) {
                    Write-Host "[CORRELATING] -> Running model: $CorrelatorName" -ForegroundColor Magenta
                    
                    $CorrelationAlerts = & $CorrelatorName -NormalizedSecurityEvents $NormalizedEvents
                    
                    if ($null -ne $CorrelationAlerts -and $CorrelationAlerts.Count -gt 0) {
                        Write-Host "   [MATCH] -> Correlator $CorrelatorName triggered execution alerts!" -ForegroundColor Red
                        foreach ($Alert in $CorrelationAlerts) { [void]$DetectedAlerts.Add($Alert) }
                    } else {
                        Write-Host "   [CLEAN] -> $CorrelatorName evaluated data. No matches found." -ForegroundColor DarkGreen
                    }
                } else {
                    Write-Host "[WARNING] -> Registered correlator '$CorrelatorName' was missing from session memory!" -ForegroundColor Yellow
                }
            } catch {
                Write-Error "Execution breakdown inside stateful correlation module [$CorrelatorName]: $_"
            }
        }

        # --- Phase C: Post-Processing Enrichment & Scoring ---
        if ($DetectedAlerts.Count -gt 0) {
            Write-Host "[ENRICHING] -> Processing $($DetectedAlerts.Count) alerts through severity calculator..." -ForegroundColor DarkCyan
            foreach ($Alert in $DetectedAlerts) {
                if (Get-Command Calculate-Severity -ErrorAction SilentlyContinue) {
                    $CalculatedValue = Calculate-Severity -Alert $Alert
                } else {
                    $CalculatedValue = "Medium" # Fallback security baseline if utility script isn't found
                }

                # Safe injection handling for PSCustomObjects and Hashtables
                if ($Alert -is [System.Collections.IDictionary] ) {
                    $Alert["Severity"] = $CalculatedValue
                }
                elseif ($null -eq $Alert.PSObject.Properties["Severity"]) {
                    $Alert | Add-Member -NotePropertyMembers @{ "Severity" = $CalculatedValue } -Force
                }
                else {
                    $Alert.Severity = $CalculatedValue
                }
            }
        }

        Write-Host "--- [END PIPELINE EVALUATION: $($DetectedAlerts.Count) ALERTS TRIGGERED] ---`n" -ForegroundColor Gray
        return $DetectedAlerts
    }
}