# ==============================================================================
# Script: ThreatHunter-Detection-Platform - XML Payload Flattening Parser
# Path:   src/Utils/ParseEventXML.ps1
# Description: Converts complex raw event log XML strings into flat, accessible objects.
# ==============================================================================

function Parse-EventXML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$RawXmlString
    )

    process {
        try {
            # Cast string data directly into a structured .NET XML Document object
            $XmlDoc = [xml]$RawXmlString
            $FlattenedObject = @{}

            # 1. Standardize core metadata properties out of the System block
            if ($null -ne $XmlDoc.Event.System) {
                $FlattenedObject["EventID"]       = [int]$XmlDoc.Event.System.EventID
                $FlattenedObject["TimeGenerated"] = [DateTime]$XmlDoc.Event.System.TimeCreated.SystemTime
                $FlattenedObject["Computer"]      = $XmlDoc.Event.System.Computer
                $FlattenedObject["ProcessId"]     = $XmlDoc.Event.System.Execution.ProcessID
            }

            # 2. Extract and flatten highly irregular variable schema key-values from EventData
            if ($null -ne $XmlDoc.Event.EventData.Data) {
                foreach ($Node in $XmlDoc.Event.EventData.Data) {
                    if ($null -ne $Node.Name) {
                        # Map internal labels (e.g., TargetUserName, CommandLine) directly to properties
                        $FlattenedObject[$Node.Name] = $Node.'#text'
                    }
                }
            }

            return [PSCustomObject]$FlattenedObject
        }
        catch {
            Write-Error "Failed to parse raw event XML structural string: $_"
            return $null
        }
    }
}