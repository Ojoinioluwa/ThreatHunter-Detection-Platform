



function Track-LogonSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$LogFile
    )

    begin{}
    process{

        $OrderedLogFile = [array]$LogFile
        [Array]::Reverse($OrderedLogFile)
        $Tracked = [System.Collections.Generic.List[object]]::new()
        $Tracker = @{}
        

        foreach($Log in $OrderedLogFile){
            if ($Log.Message -match "Account Name:\s+(?<User>\S+)") {
             $UserName = $Matches.User
            }
            # Failed Logon
            if ($Log.Id -eq 4625){

                if ($null -eq $Tracker[$UserName]) {
                    $Tracker[$UserName] = @{
                        Counter   = 0
                        StartDate = $null
                    }
                    $Tracker[$UserName].StartDate = $Log.TimeCreated
                }

                $Tracker[$UserName].Counter++
            } elseif($Log.Id -eq 4624){
                if($Tracker[$UserName].Counter -ge 5 ){
                    $Tracked.Add(@{
                        NofFailedLogon=$Tracker[$UserName].Counter
                        StartDate = $Tracker[$UserName].StartDate
                        EndDate=$Log.TimeCreated
                        UserName=$UserName
                    })
                }

                $Tracker.Remove($UserName)
            }
        }

        $Tracked

    }
    end{}
}