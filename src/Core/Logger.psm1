# ==============================================================================
# Module: ThreatHunter-Detection-Platform - System Logger
# Path:   src/Core/Logger.psm1
# Description: Manages internal platform diagnostic, error, and operational logging.
# ==============================================================================

function Write-PlatformLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR")]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$Component = "Core Engine",

        [Parameter(Mandatory = $false)]
        [string]$FileName = "platform_runtime.log"
    )

    begin {
        # Hint: Ensure your logs directory structure exists before writing to a file!
        
        $LogFolder = Join-Path $PSScriptRoot "..\..\logs"
        $LogPath = Join-Path $LogFolder $FileName
    
        $TargetDir = Split-Path $LogPath -Parent
        if (-not (Test-Path $TargetDir)){
            New-Item -Path $TargetDir -Force -ItemType Directory | Out-Null
        }
    }

    process {
        # Step 1: Build your uniform timestamp string.
        $Timestamp=(Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        # Step 2: Set up a conditional branch (or a switch block) to assign 
        # different terminal colors based on the incoming $Level.
        $TerminalColor = switch ($Level) {
            "DEBUG" {  "Blue" }
            "ERROR" {  "Red" }
            "INFO" {  "Green" }
            "WARNING" {  "Yellow" }
            Default { "Gray"}
        }
        
        # Step 3: Format your clean console text string and print it out.
        $Msg="[$Timestamp] [$Level] [$Component]: $Message"
        Write-Host "$Msg" -ForegroundColor $TerminalColor
        
        # Step 4: Format a flat text string and append it directly to your target log file path.
        Add-Content -Path $LogPath -Value $Msg
        
        Write-Output $Msg
    }
}




Export-ModuleMember -Function Write-PlatformLog