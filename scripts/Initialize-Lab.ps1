# 1. Force-import your newly designed logging module
Import-Module ".\src\Core\Logger.psm1" -Force

# 2. Fire some test entries into your engine to check execution streams and terminal colors!
Write-PlatformLog -Level "INFO" -Message "SIEM core framework initialization sequence started." -Component "Bootstrap"
Write-PlatformLog -Level "DEBUG" -Message "Resolving platform variables via PSScriptRoot anchor." -Component "ConfigLoader"
Write-PlatformLog -Level "WARNING" -Message "High volume of authentication logs detected on interface." -Component "Collector"
Write-PlatformLog -Level "ERROR" -Message "Terminating alert routing loop: disk volume read-only." -Component "OutputHandler"