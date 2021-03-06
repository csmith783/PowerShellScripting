Function Get-MachineInfo {
    # Parameter help description
    [CmdletBinding()] # Allows for common parameters of -verbose, -debug, etc 
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Alias('CN', 'MachineName', 'Name')]
        [string[]] $ComputerName, # [string[]] indicates that thsi parameter will accept an array of input values. Hardcoded to local machine
        [string] $LogFailuresToPath,
        [ValidateSet('Wsman', 'Dcom')]
        [string] $Protocol = "wsman", # this hardcodes the protocol to "wsman" unless it is otherwise specified when called
        [switch] $ProtocolFallBack
    )

    BEGIN {}

    PROCESS {
        foreach ($computer in $ComputerName) {
            # Establish session protocol
            if ($Protocol -eq 'Dcom') {
                $option = New-CimSessionOption -Protocol Dcom
            }
            else {
                $option = New-CimSessionOption -Protocol Wsman 
            }
            # Connect Session
            $session = New-CimSession -ComputerName $ComputerName -SessionOption $option

            # Query Data
            $os_params = @{'ClassName'='Win32_OperatingSystem'
                            'CimSession'=$session}
            $os = Get-CimInstance @os_params

            $cs_params = @{'ClassName'='Win32_ComputerSystem'
                            'CimSession'=$session}
            $cs = Get-CimInstance @cs_params

            $systemDrive = $os.SystemDrive
            $drive_params = @{'ClassName'='Win32_LogicalDisk'
                                'Filter'="DeviceId='$systemDrive'"
                                'CimSession'=$session}
            $drive = Get-CimInstance @drive_params

            $proc_params = @{'ClassName'='Win32_Processor'
                                'CimSession'=$session}
            $proc = Get-CimInstance @proc_params | Select-Object -First 1

            # Close Session
            Remove-CimSession -CimSession $session 

            # Output Data
            $properties = @{'ComputerName'=$computer
                                'osVersion'=$os.Version
                                'SPVersion'=$os.servicepackmajorversion
                                'OSBuild'=$os.buildnumber
                                'Manufacturer'=$cs.Manufacturer
                                'Model'=$cs.Model
                                'Procs'=$cs.numberofprocessors
                                'Cores'=$cs.numberoflogicalprocessors
                                'Ram'=($cs.totalphysicalmemory / 1GB)
                                'Architecture'=$proc.addresswidth
                                'SystemDriveFreeSpace'=$drive.freespace}
            $obj = New-Object -TypeName psobject -Property $properties

            Write-output $obj
        
        } # foreach
    } # PROCESS

    END {} 

} # Function


Function Set-ServiceLogon {
    <#
    .Synopsis
    Sets service login name and password.

    .Description
    This command uses wither CIM (default) or WMI to set the service password, and optionally the logon user name, for a service, which can be running on one or more remote machines. You must run this command as a user who has permissions to perform this task, remotely, on the computer involved.

    .Parameter ServiceName
    The name of the service. Query the Win32_Service class to verify that you know the correct name.

    .Parameter ComputerName
    One or more computer names. Using IP addresses will fail with CIM; they will work with WMI. CIM is always accepted first.

    .Parameter NewPassword
    A plain test string of the new password

    .Parameter NewUser
    Optional; the new logon user name, in DOMAIN\USER format.

    .Parameter ErrorLogFilePath
    If provided, this is a path and file name of a text file where failed computer names will be logged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] # Makes ServiceName mandatory
        [string] $ServiceName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string] $NewUser,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] #Password = mandatory
        [string] $NewPassword,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] # Computername = mandatory, accepts pipeline input by value
        [string[]] $ComputerName,

        [string] $ErrorLogFilePath
    )

    Begin {
        #Intentionally Blank
    }

    Process {

        foreach ($computer in $ComputerName) {

            do {
                Write-Verbose "Connect to $computer on WS-MAN"
                $protocol = 'Wsman"'

                Try {
                    $option = New-CimSessionOption -Protocol $protocol
                    $session = New-CimSession -ComputerName $computer -SessionOption $option

                    if ($NewUser) {
                        $args = @{'StartName' = "$NewUser"; 'StartPassword' = "$NewPassword"}
                    }
                    else {
                        $args = @{'StartPassword' = "$NewPassword"}
                        Write-warning "Not setting a new user name"
                    } #IF

                    Write-Verbose "Setting $ServiceName on $computer"
                    $cim_params = @{'Query'="Select * from Win32_Service WHERE Name='$ServiceName'"
                                'MethodName'='Change'
                                'Arguments'=$args
                                'Computername'=$computer
                                'CimSession'=$session}
            
                    $return = Invoke-CimMethod @cim_params #Splatting 

                    switch ($return.ReturnValue) {
                        0 {$status = "Success"  }
                        22 {$status = "Invalid Account"}
                        Default {$status = "Failed: $return.ReturnValue"}
                    }

                    $properties = @{'MachineName'=$computer
                                    'Status'=$status}
                    $object = New-Object -TypeName psobject -Property $properties

                    Write-Verbose "Closing connection to $computer"
                    Write-Output $object

                    $session | Remove-CimSession 
                } Catch {
                # change the protocol, and if both have already been tried, check if logging is specified, if so, log the computer
                    Switch ($protocol){
                        'Wsman'{
                            $protocol = 'Dcom'
                        } 'Dcom' {
                            $protocol = 'Stop'
                            if ($PSBoundParameters.ContainsKey('ErrorLogFilePath')){
                                Write-Warning "$computer failed; logged to $ErrorLogFilePath."
                                $computer | out-file $ErrorLogFilePath -Append
                            } # IF Logging is enabled
                        } 
                    } 

                } # Try Catch End

            } Until ($protocol -eq 'Stop')
        } #ForEach

    } #Process

    End {
        #Intentionally blank
    }

} #Function

function Get-FolderSize {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path
    )

    BEGIN {
        # Intentionally Blank
    }
    PROCESS {
        ForEach ($folder in $Path){
            Write-Verbose "Checking $folder"
            if (Test-Path -Path $folder){
                Write-Verbose "$folder Exists."

                $params = @{'Path'= $folder
                            'Recurse' = $true
                            'File' = $true
                }

                $measure = get-childitem @params | Measure-Object -Property Length -Sum
                [pscustomobject]@{'Path' = $folder
                                    'Files' = $measure.Count
                                    'Bytes' = $measure.Sum}
            } else {
                Write-Verbose "$folder does not exist."
                [PSCustomObject]@{
                    'Path' = $folder
                    'Files' = 0
                    'Bytes' = 0
                }
            }
        }
    }
    END {
        # Intentionally left blank
    }
}

function Get-UserHomeFolderInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string] $HomeRootPath
    )

    BEGIN {
        # Intentionally left blank
    }

    PROCESS {
        Write-Verbose "Enumerating $HomeRootPath"
        $params = @{
                'Path' = $HomeRootPath
                'Directory' = $true
        }

        foreach ($folder in (Get-childitem @params)) {
            write-verbose "Checking $(folder.name)"
            $params = @{
                'Identity' = $folder.Name
                'ErrorAction' = 'SilentlyContinue'
            }
            $user = get-aduser @params

            if ($user) {
                Write-Verbose " + User Exists."
                $result = get-foldersize -Path $folder.fullname
                [PSCustomObject]@{
                    'user' = $folder.Name 
                    'Path' = $folder.fullname
                    'Files' = $result.Files
                    'Bytes' = $result.Bytes
                    'Status' = 'OK'
                }
            } else {
                Write-verbose " - User does not exist."
                [PSCustomObject]@{
                    'user' = $folder.Name 
                    'Path' = $folder.fullname
                    'Files' = 0
                    'Bytes' = 0
                    'Status' = 'Orphan'
                }
            }
        }
    }

    END {
        # Intentionally left blank
    }
}
