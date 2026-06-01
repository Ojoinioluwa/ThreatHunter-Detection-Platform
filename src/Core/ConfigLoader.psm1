function New-PlatformConfig {
    [CmdletBinding()]
    param()
    dynamicparam {}
    begin {}
    process {}
    end {}
}

Class PlatformConfig {
    [string]$ConfigPath
    [hashtable]$EventIDs
    [hashtable]$Thresholds
    [hashtable]$SeverityMap

    PlatformConfig([string]$RootPath) {
        $this.ConfigPath = $RootPath
        $this.LoadConfiguration()
    }

    [void] LoadConfiguration() {
        # Helper closure to safely ingest and parse JSON files
        $GetJsonContent = {
            param([string]$FileName)
            $FullPath = Join-Path $this.ConfigPath $FileName
            if (Test-Path $FullPath) {
                return Get-Content -Raw $FullPath | ConvertFrom-Json -AsHashtable
            }
            throw "Critical configuration file missing: $FullPath"
        }

        # Load your discrete configurations into unified class properties
        $this.EventIDs    = &$GetJsonContent -FileName "eventids.json"
        $this.Thresholds  = &$GetJsonContent -FileName "thresholds.json"
        $this.SeverityMap = &$GetJsonContent -FileName "severitymap.json"

    }
}


function Initialize-Config {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigRoot
    )
    process {
        # Instantiates the configuration object to be consumed by the platform wrapper
        return [PlatformConfig]::new($ConfigRoot)
    }
}

Export-ModuleMember -Function Initialize-Config