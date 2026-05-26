
function Get-TelemetryBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [int[]]$EventIDs,

        [Parameter(Mandatory = $true)]
        [int]$WindowHours
    )
    process {
        # lookback time boundary
        $StartTime = (Get-Date).AddHours(-$WindowHours)

        $FilterHashtable = @{
            LogName   = $LogName
            ID        = $EventIDs
            StartTime = $StartTime
        }

        # Query the Windows Event Subsystem using the high-performance provider layer
        $RawEvents = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue

        if ($null -eq $RawEvents) {
            # Emit an empty array cleanly so downstream detection engines don't break on null collections
            return [System.Collections.Generic.List[object]]::new()
        }

        # Return the collection down the pipeline
        return $RawEvents
    }
}

Export-ModuleMember -Function Get-TelemetryBatch