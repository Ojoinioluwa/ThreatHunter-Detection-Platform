# ==============================================================================
# Module: ThreatHunter-Detection-Platform - Correlator Anchor Manifest
# Path:   src/Core/Correlator.psm1
# Description: Main entry point that loads standalone script logic files into memory.
# ==============================================================================

# Define path routing to the decoupled script files directory
$CorrelatorDir = Join-Path $PSScriptRoot "../Correlator"

# Automatically load the dedicated logic modules into the runtime scope
. (Join-Path $CorrelatorDir "LoginSequence.ps1")
. (Join-Path $CorrelatorDir "AccountEscalation.ps1")

# Export them cleanly to the rest of your automation execution environment
Export-ModuleMember -Function Track-LogonSequence, Track-AccountEscalation