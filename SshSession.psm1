#Requires -Version 7.0

$script:AskPassPath = Join-Path $PSScriptRoot 'ssh-askpass.cmd'

function New-SshSession {
    <#
    .SYNOPSIS
        Creates a new PSSession over SSH with optional credential support.
    
    .DESCRIPTION
        Wraps New-PSSession for SSH connections, adding support for PSCredential objects
        by configuring SSH_ASKPASS automatically. Returns a standard PSSession that works
        with all native PowerShell remoting cmdlets.
    
    .PARAMETER ComputerName
        The hostname or IP address of the remote computer.
    
    .PARAMETER Credential
        Optional PSCredential object. If not specified, SSH will use default key-based authentication.
    
    .PARAMETER UserName
        Optional username. If Credential is provided, the username from the credential is used instead.
    
    .PARAMETER Port
        SSH port. Defaults to 22.
    
    .PARAMETER Options
        Additional SSH options as a hashtable, passed to New-PSSession -Options.
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -Credential (Get-Credential)
        Invoke-Command -Session $session -ScriptBlock { Get-Process }
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -UserName admin
        # Uses SSH key authentication for 'admin' user
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ComputerName,

        [Parameter(Position = 1)]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$UserName,

        [Parameter()]
        [int]$Port = 22,

        [Parameter()]
        [hashtable]$Options
    )

    $sessionParams = @{
        HostName = $ComputerName
        Port     = $Port
    }

    if ($Options) {
        $sessionParams['Options'] = $Options
    }

    if ($Credential) {
        $sessionParams['UserName'] = $Credential.UserName
        
        $originalAskPass = $env:SSH_ASKPASS
        $originalDisplay = $env:DISPLAY
        $originalPassword = $env:SSH_CREDENTIAL_PASSWORD
        $originalAskPassRequire = $env:SSH_ASKPASS_REQUIRE

        try {
            $env:SSH_ASKPASS = $script:AskPassPath
            $env:DISPLAY = 'required_for_askpass'
            $env:SSH_CREDENTIAL_PASSWORD = $Credential.GetNetworkCredential().Password
            $env:SSH_ASKPASS_REQUIRE = 'force'

            New-PSSession @sessionParams
        }
        finally {
            # Restore original environment
            if ($null -eq $originalAskPass) { Remove-Item Env:SSH_ASKPASS -ErrorAction SilentlyContinue }
            else { $env:SSH_ASKPASS = $originalAskPass }

            if ($null -eq $originalDisplay) { Remove-Item Env:DISPLAY -ErrorAction SilentlyContinue }
            else { $env:DISPLAY = $originalDisplay }

            if ($null -eq $originalPassword) { Remove-Item Env:SSH_CREDENTIAL_PASSWORD -ErrorAction SilentlyContinue }
            else { $env:SSH_CREDENTIAL_PASSWORD = $originalPassword }

            if ($null -eq $originalAskPassRequire) { Remove-Item Env:SSH_ASKPASS_REQUIRE -ErrorAction SilentlyContinue }
            else { $env:SSH_ASKPASS_REQUIRE = $originalAskPassRequire }
        }
    }
    else {
        if ($UserName) {
            $sessionParams['UserName'] = $UserName
        }
        New-PSSession @sessionParams
    }
}

function Invoke-SshCommand {
    <#
    .SYNOPSIS
        Invokes a command on a remote computer over SSH.
    
    .DESCRIPTION
        Convenience wrapper around Invoke-Command for SSH sessions. Supports credential-based
        authentication for one-liner scenarios. If a session is not provided but credentials are,
        creates an ephemeral session for the command.
    
    .PARAMETER ComputerName
        The hostname or IP address of the remote computer. Required if Session is not provided.
    
    .PARAMETER Session
        An existing PSSession to use. If provided, ComputerName and Credential are ignored.
    
    .PARAMETER Credential
        Optional PSCredential for authentication. Creates an ephemeral session if Session is not provided.
    
    .PARAMETER ScriptBlock
        The script block to execute on the remote computer.
    
    .PARAMETER ArgumentList
        Arguments to pass to the script block.
    
    .PARAMETER UserName
        Optional username for key-based authentication when Credential is not provided.
    
    .PARAMETER Port
        SSH port. Defaults to 22.
    
    .EXAMPLE
        Invoke-SshCommand -ComputerName server01 -Credential $cred -ScriptBlock { Get-Service W32Time }
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -Credential $cred
        Invoke-SshCommand -Session $session -ScriptBlock { Get-Process | Select-Object -First 5 }
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ComputerName')]
        [string]$ComputerName,

        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(ParameterSetName = 'ComputerName')]
        [PSCredential]$Credential,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [object[]]$ArgumentList,

        [Parameter(ParameterSetName = 'ComputerName')]
        [string]$UserName,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$Port = 22
    )

    $invokeParams = @{
        ScriptBlock = $ScriptBlock
    }

    if ($ArgumentList) {
        $invokeParams['ArgumentList'] = $ArgumentList
    }

    $ephemeralSession = $null

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Session') {
            $invokeParams['Session'] = $Session
        }
        else {
            $sessionParams = @{
                ComputerName = $ComputerName
                Port         = $Port
            }

            if ($Credential) {
                $sessionParams['Credential'] = $Credential
            }
            elseif ($UserName) {
                $sessionParams['UserName'] = $UserName
            }

            $ephemeralSession = New-SshSession @sessionParams
            $invokeParams['Session'] = $ephemeralSession
        }

        Invoke-Command @invokeParams
    }
    finally {
        if ($ephemeralSession) {
            Remove-PSSession $ephemeralSession -ErrorAction SilentlyContinue
        }
    }
}

function Send-SshFile {
    <#
    .SYNOPSIS
        Copies files to a remote computer over an SSH session.
    
    .DESCRIPTION
        Wraps Copy-Item -ToSession for SSH-based file transfers. Supports credential-based
        authentication for one-liner scenarios.
    
    .PARAMETER Path
        Local path(s) of files or folders to send.
    
    .PARAMETER Destination
        Destination path on the remote computer.
    
    .PARAMETER ComputerName
        The hostname or IP address of the remote computer. Required if Session is not provided.
    
    .PARAMETER Session
        An existing PSSession to use.
    
    .PARAMETER Credential
        Optional PSCredential for authentication.
    
    .PARAMETER UserName
        Optional username for key-based authentication.
    
    .PARAMETER Port
        SSH port. Defaults to 22.
    
    .PARAMETER Recurse
        Copy directories recursively.
    
    .PARAMETER Force
        Overwrite existing files.
    
    .EXAMPLE
        Send-SshFile -Path .\config.json -Destination /etc/myapp/ -ComputerName server01 -Credential $cred
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -Credential $cred
        Send-SshFile -Path .\scripts\ -Destination /opt/scripts/ -Session $session -Recurse
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Path,

        [Parameter(Mandatory, Position = 1)]
        [string]$Destination,

        [Parameter(Mandatory, ParameterSetName = 'ComputerName')]
        [string]$ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(ParameterSetName = 'ComputerName')]
        [PSCredential]$Credential,

        [Parameter(ParameterSetName = 'ComputerName')]
        [string]$UserName,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$Port = 22,

        [Parameter()]
        [switch]$Recurse,

        [Parameter()]
        [switch]$Force
    )

    $copyParams = @{
        Path        = $Path
        Destination = $Destination
    }

    if ($Recurse) { $copyParams['Recurse'] = $true }
    if ($Force) { $copyParams['Force'] = $true }

    $ephemeralSession = $null

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Session') {
            $copyParams['ToSession'] = $Session
        }
        else {
            $sessionParams = @{
                ComputerName = $ComputerName
                Port         = $Port
            }

            if ($Credential) {
                $sessionParams['Credential'] = $Credential
            }
            elseif ($UserName) {
                $sessionParams['UserName'] = $UserName
            }

            $ephemeralSession = New-SshSession @sessionParams
            $copyParams['ToSession'] = $ephemeralSession
        }

        Copy-Item @copyParams
    }
    finally {
        if ($ephemeralSession) {
            Remove-PSSession $ephemeralSession -ErrorAction SilentlyContinue
        }
    }
}

function Receive-SshFile {
    <#
    .SYNOPSIS
        Copies files from a remote computer over an SSH session.
    
    .DESCRIPTION
        Wraps Copy-Item -FromSession for SSH-based file transfers. Supports credential-based
        authentication for one-liner scenarios.
    
    .PARAMETER Path
        Remote path(s) of files or folders to receive.
    
    .PARAMETER Destination
        Local destination path.
    
    .PARAMETER ComputerName
        The hostname or IP address of the remote computer. Required if Session is not provided.
    
    .PARAMETER Session
        An existing PSSession to use.
    
    .PARAMETER Credential
        Optional PSCredential for authentication.
    
    .PARAMETER UserName
        Optional username for key-based authentication.
    
    .PARAMETER Port
        SSH port. Defaults to 22.
    
    .PARAMETER Recurse
        Copy directories recursively.
    
    .PARAMETER Force
        Overwrite existing files.
    
    .EXAMPLE
        Receive-SshFile -Path /var/log/myapp.log -Destination .\logs\ -ComputerName server01 -Credential $cred
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -Credential $cred
        Receive-SshFile -Path /etc/myapp/ -Destination .\backup\ -Session $session -Recurse
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Path,

        [Parameter(Mandatory, Position = 1)]
        [string]$Destination,

        [Parameter(Mandatory, ParameterSetName = 'ComputerName')]
        [string]$ComputerName,

        [Parameter(Mandatory, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(ParameterSetName = 'ComputerName')]
        [PSCredential]$Credential,

        [Parameter(ParameterSetName = 'ComputerName')]
        [string]$UserName,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$Port = 22,

        [Parameter()]
        [switch]$Recurse,

        [Parameter()]
        [switch]$Force
    )

    $copyParams = @{
        Path        = $Path
        Destination = $Destination
    }

    if ($Recurse) { $copyParams['Recurse'] = $true }
    if ($Force) { $copyParams['Force'] = $true }

    $ephemeralSession = $null

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Session') {
            $copyParams['FromSession'] = $Session
        }
        else {
            $sessionParams = @{
                ComputerName = $ComputerName
                Port         = $Port
            }

            if ($Credential) {
                $sessionParams['Credential'] = $Credential
            }
            elseif ($UserName) {
                $sessionParams['UserName'] = $UserName
            }

            $ephemeralSession = New-SshSession @sessionParams
            $copyParams['FromSession'] = $ephemeralSession
        }

        Copy-Item @copyParams
    }
    finally {
        if ($ephemeralSession) {
            Remove-PSSession $ephemeralSession -ErrorAction SilentlyContinue
        }
    }
}

Export-ModuleMember -Function New-SshSession, Invoke-SshCommand, Send-SshFile, Receive-SshFile