# ==============================================================================
# Script: ThreatHunter-Detection-Platform - New Service Installation Detector
# Path:   src/Detection/Host/Detect-ServiceInstall.ps1
# Description: Instantly flags the creation of newly registered background services.
# ==============================================================================

function Detect-ServiceInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$NormalizedSecurityEvents
    )

    process {
        $DetectedThreats = [System.Collections.Generic.List[object]]::new()

        foreach ($Log in $NormalizedSecurityEvents) {
            # Event ID 7045: A service was successfully installed in the system
            if ($Log.EventID -eq 7045) {
                
                # Escalate severity if the background service uses command shells instead of real binary files
                $Severity = "Medium"
                if ($Log.ImagePath -like "*cmd.exe*" -or $Log.ImagePath -like "*powershell*" -or $Log.ImagePath -like "*comspec*") {
                    $Severity = "Critical" # Definite malicious service wrapper behavior
                }

                $DetectedThreats.Add([PSCustomObject]@{
                    Timestamp     = $Log.TimeGenerated
                    DetectionType = "New Windows Service Installation"
                    MITRE_ID      = "T1543.003"   # Create or Modify System Process: Windows Service
                    Severity      = $Severity
                    Computer      = $Log.Computer
                    User          = $Log.User     # The administrator or system context installing the driver/service
                    Description   = "A new background service wrapper was registered into the Service Control Manager database registry entries."
                    Evidence      = @{
                        ServiceName = $Log.ServiceName # e.g., PseXec
                        ImagePath   = $Log.ImagePath   # e.g., C:\Windows\System32\cmd.exe /c ...
                        ServiceType = $Log.ServiceType
                        StartType   = $Log.StartType   # e.g., Auto Start, Demand Start
                        EventID     = $Log.EventID
                    }
                })
            }
        }

        return $DetectedThreats
    }
}