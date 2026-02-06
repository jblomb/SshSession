#Requires -Version 7.0

$script:AskPassPath = Join-Path $PSScriptRoot 'ssh-askpass.cmd'
$script:OriginalSshEnv = $null

#region Private Functions

function Set-SshAskpassEnvironment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCredential]$Credential
    )

    # Store original values for restoration
    $script:OriginalSshEnv = @{
        SSH_ASKPASS             = $env:SSH_ASKPASS
        DISPLAY                 = $env:DISPLAY
        SSH_CREDENTIAL_PASSWORD = $env:SSH_CREDENTIAL_PASSWORD
        SSH_ASKPASS_REQUIRE     = $env:SSH_ASKPASS_REQUIRE
    }

    $env:SSH_ASKPASS = $script:AskPassPath
    $env:DISPLAY = 'required_for_askpass'
    $env:SSH_CREDENTIAL_PASSWORD = $Credential.GetNetworkCredential().Password
    $env:SSH_ASKPASS_REQUIRE = 'force'
}

function Remove-SshAskpassEnvironment {
    [CmdletBinding()]
    param()

    if (-not $script:OriginalSshEnv) {
        return
    }

    foreach ($var in $script:OriginalSshEnv.Keys) {
        if ($null -eq $script:OriginalSshEnv[$var]) {
            Remove-Item "Env:$var" -ErrorAction SilentlyContinue
        }
        else {
            Set-Item "Env:$var" -Value $script:OriginalSshEnv[$var]
        }
    }

    $script:OriginalSshEnv = $null
}

#endregion Private Functions

#region Public Functions

function Test-SshConnection {
    <#
    .SYNOPSIS
        Tests SSH connectivity to a remote host with timeout protection.
    
    .DESCRIPTION
        Performs a quick SSH connection test by executing a simple PowerShell command
        on the remote host. Uses a background job with timeout to prevent hanging
        on unreachable hosts. Tests the full connection path including any ProxyJump
        configurations in your SSH config.
    
    .PARAMETER ComputerName
        The hostname or IP address to test. This should match a host entry in your
        SSH config if using bastion/ProxyJump configurations.
    
    .PARAMETER Credential
        Optional PSCredential object for password-based authentication.
    
    .PARAMETER UserName
        Optional username for key-based authentication.
    
    .PARAMETER TimeoutSeconds
        Maximum seconds to wait for connection. Defaults to 30.
    
    .PARAMETER Port
        SSH port. Defaults to 22.
    
    .EXAMPLE
        Test-SshConnection -ComputerName server01
        # Returns $true if connection succeeds
    
    .EXAMPLE
        if (Test-SshConnection -ComputerName server01 -TimeoutSeconds 10) {
            $session = New-SshSession -ComputerName server01
        }
    
    .EXAMPLE
        Test-SshConnection -ComputerName customer-server -Credential $cred
        # Tests connection with password authentication through any configured bastion hops
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ComputerName,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [string]$UserName,

        [Parameter()]
        [int]$TimeoutSeconds = 30,

        [Parameter()]
        [int]$Port = 22
    )

    # Determine username for SSH target
    $effectiveUserName = if ($Credential) { $Credential.UserName } elseif ($UserName) { $UserName } else { $null }
    $sshTarget = if ($effectiveUserName) { "$effectiveUserName@$ComputerName" } else { $ComputerName }

    # Simple test command - returns 'OK!' if PowerShell runs successfully
    $testScript = "Return 'OK!'"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($testScript)
    $encodedCommand = [Convert]::ToBase64String($bytes)

    # Build SSH command with strict host key checking disabled for automation
    # When using credentials, force password auth only to prevent key fallback
    $sshOptions = "-o StrictHostKeyChecking=no -o ConnectTimeout=$TimeoutSeconds"
    if ($Credential) {
        $sshOptions += " -o PreferredAuthentications=password -o PubkeyAuthentication=no"
    }
    
    $sshCommand = "ssh $sshOptions -p $Port $sshTarget 'pwsh -e $encodedCommand'"
    $scriptBlock = [scriptblock]::Create($sshCommand)

    Write-Verbose "Testing SSH connection: $sshCommand"

    $job = $null
    try {
        if ($Credential) {
            Set-SshAskpassEnvironment -Credential $Credential
        }

        $job = Start-Job -ScriptBlock $scriptBlock
        $completed = Wait-Job -Job $job -Timeout $TimeoutSeconds

        if (-not $completed) {
            Write-Verbose "SSH connection to '$ComputerName' timed out after $TimeoutSeconds seconds."
            return $false
        }

        if ($job.State -eq 'Failed') {
            $errorInfo = Receive-Job -Job $job -ErrorAction SilentlyContinue
            Write-Verbose "SSH connection to '$ComputerName' failed: $errorInfo"
            return $false
        }

        $result = Receive-Job -Job $job

        if ($result -eq 'OK!') {
            Write-Verbose "SSH connection test successful."
            return $true
        }
        else {
            Write-Verbose "SSH connection to '$ComputerName' failed. Unexpected response: $result"
            return $false
        }
    }
    catch {
        Write-Verbose "SSH connection to '$ComputerName' failed: $_"
        return $false
    }
    finally {
        if ($Credential) {
            Remove-SshAskpassEnvironment
        }
        if ($job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
}

function New-SshSession {
    <#
    .SYNOPSIS
        Creates a new PSSession over SSH with optional credential support.
    
    .DESCRIPTION
        Wraps New-PSSession for SSH connections, adding support for PSCredential objects
        by configuring SSH_ASKPASS automatically. Returns a standard PSSession that works
        with all native PowerShell remoting cmdlets.
        
        By default, tests connectivity before creating the session to avoid hanging on
        unreachable hosts. Use -SkipTest to bypass this check.
    
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
    
    .PARAMETER SkipTest
        Skip the connectivity test before creating the session. Use when you're confident
        the host is reachable or when the test overhead is undesirable.
    
    .PARAMETER TestTimeoutSeconds
        Timeout for the connectivity test. Defaults to 30 seconds. Ignored if -SkipTest is specified.
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -Credential (Get-Credential)
        Invoke-Command -Session $session -ScriptBlock { Get-Process }
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -UserName admin
        # Uses SSH key authentication for 'admin' user
    
    .EXAMPLE
        $session = New-SshSession -ComputerName server01 -SkipTest
        # Skips connectivity test for faster session creation
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
        [hashtable]$Options,

        [Parameter()]
        [switch]$SkipTest,

        [Parameter()]
        [int]$TestTimeoutSeconds = 30
    )

    # Test connectivity first unless skipped
    if (-not $SkipTest) {
        $testParams = @{
            ComputerName   = $ComputerName
            Port           = $Port
            TimeoutSeconds = $TestTimeoutSeconds
        }

        if ($Credential) {
            $testParams['Credential'] = $Credential
        }
        elseif ($UserName) {
            $testParams['UserName'] = $UserName
        }

        if (-not (Test-SshConnection @testParams)) {
            throw "SSH connection test to '$ComputerName' failed. Use -Verbose for details or -SkipTest to bypass."
        }
    }

    $sessionParams = @{
        HostName = $ComputerName
        Port     = $Port
    }

    if ($Options) {
        $sessionParams['Options'] = $Options
    }

    if ($Credential) {
        $sessionParams['UserName'] = $Credential.UserName
        
        # Force password-only auth to prevent key fallback
        $sshOptions = @{
            PreferredAuthentications = 'password'
            PubkeyAuthentication     = 'no'
        }
        
        # Merge with any user-provided options (user options take precedence)
        if ($sessionParams['Options']) {
            foreach ($key in $sshOptions.Keys) {
                if (-not $sessionParams['Options'].ContainsKey($key)) {
                    $sessionParams['Options'][$key] = $sshOptions[$key]
                }
            }
        }
        else {
            $sessionParams['Options'] = $sshOptions
        }

        try {
            Set-SshAskpassEnvironment -Credential $Credential
            New-PSSession @sessionParams
        }
        finally {
            Remove-SshAskpassEnvironment
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
    
    .PARAMETER SkipTest
        Skip the connectivity test before creating the session.
    
    .PARAMETER TestTimeoutSeconds
        Timeout for the connectivity test. Defaults to 30 seconds. Ignored if -SkipTest is specified.
    
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
        [int]$Port = 22,

        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]$SkipTest,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$TestTimeoutSeconds = 30
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
                ComputerName       = $ComputerName
                Port               = $Port
                SkipTest           = $SkipTest
                TestTimeoutSeconds = $TestTimeoutSeconds
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
    
    .PARAMETER SkipTest
        Skip the connectivity test before creating the session.
    
    .PARAMETER TestTimeoutSeconds
        Timeout for the connectivity test. Defaults to 30 seconds. Ignored if -SkipTest is specified.
    
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
        [switch]$Force,

        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]$SkipTest,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$TestTimeoutSeconds = 30
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
                ComputerName       = $ComputerName
                Port               = $Port
                SkipTest           = $SkipTest
                TestTimeoutSeconds = $TestTimeoutSeconds
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
    
    .PARAMETER SkipTest
        Skip the connectivity test before creating the session.
    
    .PARAMETER TestTimeoutSeconds
        Timeout for the connectivity test. Defaults to 30 seconds. Ignored if -SkipTest is specified.
    
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
        [switch]$Force,

        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]$SkipTest,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$TestTimeoutSeconds = 30
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
                ComputerName       = $ComputerName
                Port               = $Port
                SkipTest           = $SkipTest
                TestTimeoutSeconds = $TestTimeoutSeconds
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

#endregion Public Functions

Export-ModuleMember -Function Test-SshConnection, New-SshSession, Invoke-SshCommand, Send-SshFile, Receive-SshFile