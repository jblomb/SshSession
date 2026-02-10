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

function Get-SshSessionInfo {
    <# Extracts ComputerName, UserName, and Port from an existing PSSession. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $computerName = $Session.ComputerName
    $userName = $Session.Runspace.ConnectionInfo.UserName

    try {
        $sessionPort = $Session.Runspace.ConnectionInfo.Port
        $port = if ($sessionPort -and $sessionPort -gt 0) { $sessionPort } else { 22 }
    }
    catch {
        $port = 22
    }

    # Extract stored credential if present (attached by New-SshSession)
    $credential = $null
    if ($Session.PSObject.Properties['Credential']) {
        $credential = $Session.Credential
    }

    return @{
        ComputerName = $computerName
        UserName     = $userName
        Port         = $port
        Credential   = $credential
    }
}

function Copy-SshSession {
    <#
        Replaces the internals of an existing PSSession with those from a new session
        using reflection. This updates the caller's session variable in-place so it
        points to a working connection without requiring reassignment.

        The original session's Id, Name, and InstanceId are preserved so the variable
        identity stays consistent from the caller's perspective.

        Note: The updated session will not appear in Get-PSSession since the session
        registry still tracks the original (now-hollow) entry. This is acceptable for
        sessions managed by the caller's variable, and all objects are cleaned up when
        the PowerShell process exits.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$OldSession,

        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$NewSession
    )

    $type = [System.Management.Automation.Runspaces.PSSession]

    # Preserve identity fields
    $oldId = $OldSession.Id
    $oldName = $OldSession.Name
    $oldInstanceId = $OldSession.InstanceId

    # Copy all fields from new session to old session
    foreach ($field in $type.GetFields('NonPublic,Instance')) {
        try {
            $field.SetValue($OldSession, $field.GetValue($NewSession))
        }
        catch {
            Write-Verbose "Could not copy field '$($field.Name)': $_"
        }
    }

    # Restore identity fields so the caller's variable looks the same
    $identityFields = @{
        '<Id>k__BackingField'         = $oldId
        '<Name>k__BackingField'       = $oldName
        '<InstanceId>k__BackingField' = $oldInstanceId
    }

    foreach ($entry in $identityFields.GetEnumerator()) {
        $field = $type.GetField($entry.Key, 'NonPublic,Instance')
        if ($field) {
            $field.SetValue($OldSession, $entry.Value)
        }
        else {
            Write-Verbose "Identity field '$($entry.Key)' not found. .NET runtime may have changed backing field names."
        }
    }

    Write-Verbose "Refreshed session '$oldName' (Id: $oldId) with connection from session $($NewSession.Id)."

    # Preserve stored credential (NoteProperty attached by New-SshSession)
    if ($NewSession.PSObject.Properties['Credential']) {
        if ($OldSession.PSObject.Properties['Credential']) {
            $OldSession.Credential = $NewSession.Credential
        }
        else {
            $OldSession | Add-Member -NotePropertyName 'Credential' -NotePropertyValue $NewSession.Credential -Force
        }
    }
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
            Write-Verbose "SSH connection to '$ComputerName' succeeded."
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
        
        When a credential is provided, it is stored on the session object as a NoteProperty
        so that other functions can automatically repair the session without requiring the
        credential to be passed again.
        
        By default, tests connectivity before creating the session to avoid hanging on
        unreachable hosts. Use -SkipTest to bypass this check.
        
        Can also accept an existing PSSession via -Session to create a fresh replacement
        session using the same connection details. This is useful for repairing broken or
        disconnected sessions. The old session is removed automatically.
    
    .PARAMETER ComputerName
        The hostname or IP address of the remote computer.
    
    .PARAMETER Session
        An existing PSSession to replace. Connection details (ComputerName, UserName, Port)
        are extracted from the session. If the session has a stored credential and -Credential
        is not provided, the stored credential is used automatically. The old session is
        removed after the new one is created.
    
    .PARAMETER Credential
        Optional PSCredential object. If not specified, SSH will use default key-based authentication.
    
    .PARAMETER UserName
        Optional username. If Credential is provided, the username from the credential is used instead.
    
    .PARAMETER Port
        SSH port. Defaults to 22, or the port from the original session when using -Session.
    
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
    
    .EXAMPLE
        $session = New-SshSession -Session $session -Credential $cred
        # Repairs a broken session by creating a fresh one with the same connection details
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    [OutputType([System.Management.Automation.Runspaces.PSSession])]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ComputerName')]
        [string]$ComputerName,

        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Session')]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter(Position = 1)]
        [PSCredential]$Credential,

        [Parameter(ParameterSetName = 'ComputerName')]
        [string]$UserName,

        [Parameter()]
        [int]$Port,

        [Parameter()]
        [hashtable]$Options,

        [Parameter()]
        [switch]$SkipTest,

        [Parameter()]
        [int]$TestTimeoutSeconds = 30
    )

    # If Session is provided, extract connection info and remove the old session
    if ($PSCmdlet.ParameterSetName -eq 'Session') {
        $info = Get-SshSessionInfo -Session $Session
        $ComputerName = $info.ComputerName

        if (-not $PSBoundParameters.ContainsKey('Port')) {
            $Port = $info.Port
        }

        # Fall back to stored credential if no explicit credential provided
        if (-not $Credential -and $info.Credential) {
            $Credential = $info.Credential
            Write-Verbose "Using stored credential from session for '$ComputerName'."
        }

        if (-not $Credential -and $info.UserName) {
            $UserName = $info.UserName
        }

        Write-Verbose "Replacing session to '$ComputerName' (Id: $($Session.Id))."
        Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
    }

    # Default port if not explicitly set
    if (-not $PSBoundParameters.ContainsKey('Port') -and $PSCmdlet.ParameterSetName -ne 'Session') {
        $Port = 22
    }

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

    Write-Verbose "Creating SSH session to '$ComputerName' on port $Port."

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
            $newSession = New-PSSession @sessionParams
            $newSession | Add-Member -NotePropertyName 'Credential' -NotePropertyValue $Credential -Force
            $newSession
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
        
        When -Session is the only connection parameter, the existing session is used directly
        for command execution. If the session is broken and has a stored credential (or an
        explicit -Credential is provided), it is repaired in-place automatically. The repair
        updates the caller's session variable via reflection, so it remains usable after the
        command completes.
    
    .PARAMETER ComputerName
        The hostname or IP address of the remote computer. Required if Session is not provided.
    
    .PARAMETER Session
        An existing PSSession to use for command execution. When used alone, the session is
        used as-is. When combined with -Credential, the session is repaired first.
    
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
        [Parameter(ParameterSetName = 'Session')]
        [PSCredential]$Credential,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [object[]]$ArgumentList,

        [Parameter(ParameterSetName = 'ComputerName')]
        [string]$UserName,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$Port = 22,

        [Parameter()]
        [switch]$SkipTest,

        [Parameter()]
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
            # Resolve credential: explicit parameter > stored on session
            $effectiveCredential = if ($Credential) { $Credential }
                elseif ($Session.PSObject.Properties['Credential']) { $Session.Credential }
                else { $null }

            if ($effectiveCredential -and $Session.State -ne 'Opened') {
                # Repair the broken session in-place
                Write-Verbose "Session to '$($Session.ComputerName)' is in state '$($Session.State)'. Repairing in-place before invoking command."
                $repairParams = @{
                    Session            = $Session
                    Credential         = $effectiveCredential
                    SkipTest           = $SkipTest
                    TestTimeoutSeconds = $TestTimeoutSeconds
                }
                $repairedSession = New-SshSession @repairParams
                Copy-SshSession -OldSession $Session -NewSession $repairedSession

                # Update stored credential if an explicit override was provided
                if ($Credential) {
                    $Session | Add-Member -NotePropertyName 'Credential' -NotePropertyValue $Credential -Force
                }

                $invokeParams['Session'] = $Session
            }
            else {
                $invokeParams['Session'] = $Session
                Write-Verbose "Invoking command on existing session '$($Session.ComputerName)'."
            }
        }
        else {
            Write-Verbose "Invoking command on '$ComputerName'."
            
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
        An existing PSSession to use. When used alone, the session is used directly.
        When combined with -Credential, the session is repaired in-place first if it is
        not in the 'Opened' state, so the caller's variable remains usable afterward.
    
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
    
    .EXAMPLE
        Send-SshFile -Path .\config.json -Destination /etc/myapp/ -Session $session -Credential $cred
        # Repairs a broken session before sending files
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
        [Parameter(ParameterSetName = 'Session')]
        [PSCredential]$Credential,

        [Parameter(ParameterSetName = 'ComputerName')]
        [string]$UserName,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$Port = 22,

        [Parameter()]
        [switch]$Recurse,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$SkipTest,

        [Parameter()]
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
            # Resolve credential: explicit parameter > stored on session
            $effectiveCredential = if ($Credential) { $Credential }
                elseif ($Session.PSObject.Properties['Credential']) { $Session.Credential }
                else { $null }

            if ($effectiveCredential -and $Session.State -ne 'Opened') {
                Write-Verbose "Session to '$($Session.ComputerName)' is in state '$($Session.State)'. Repairing in-place before sending files."
                $repairParams = @{
                    Session            = $Session
                    Credential         = $effectiveCredential
                    SkipTest           = $SkipTest
                    TestTimeoutSeconds = $TestTimeoutSeconds
                }
                $repairedSession = New-SshSession @repairParams
                Copy-SshSession -OldSession $Session -NewSession $repairedSession

                # Update stored credential if an explicit override was provided
                if ($Credential) {
                    $Session | Add-Member -NotePropertyName 'Credential' -NotePropertyValue $Credential -Force
                }

                $copyParams['ToSession'] = $Session
            }
            else {
                $copyParams['ToSession'] = $Session
                Write-Verbose "Sending file(s) to existing session '$($Session.ComputerName)'."
            }
        }
        else {
            Write-Verbose "Sending file(s) to '$ComputerName'."
            
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
        An existing PSSession to use. When used alone, the session is used directly.
        When combined with -Credential, the session is repaired in-place first if it is
        not in the 'Opened' state, so the caller's variable remains usable afterward.
    
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
    
    .EXAMPLE
        Receive-SshFile -Path /var/log/app.log -Destination .\logs\ -Session $session -Credential $cred
        # Repairs a broken session before receiving files
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
        [Parameter(ParameterSetName = 'Session')]
        [PSCredential]$Credential,

        [Parameter(ParameterSetName = 'ComputerName')]
        [string]$UserName,

        [Parameter(ParameterSetName = 'ComputerName')]
        [int]$Port = 22,

        [Parameter()]
        [switch]$Recurse,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$SkipTest,

        [Parameter()]
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
            # Resolve credential: explicit parameter > stored on session
            $effectiveCredential = if ($Credential) { $Credential }
                elseif ($Session.PSObject.Properties['Credential']) { $Session.Credential }
                else { $null }

            if ($effectiveCredential -and $Session.State -ne 'Opened') {
                Write-Verbose "Session to '$($Session.ComputerName)' is in state '$($Session.State)'. Repairing in-place before receiving files."
                $repairParams = @{
                    Session            = $Session
                    Credential         = $effectiveCredential
                    SkipTest           = $SkipTest
                    TestTimeoutSeconds = $TestTimeoutSeconds
                }
                $repairedSession = New-SshSession @repairParams
                Copy-SshSession -OldSession $Session -NewSession $repairedSession

                # Update stored credential if an explicit override was provided
                if ($Credential) {
                    $Session | Add-Member -NotePropertyName 'Credential' -NotePropertyValue $Credential -Force
                }

                $copyParams['FromSession'] = $Session
            }
            else {
                $copyParams['FromSession'] = $Session
                Write-Verbose "Receiving file(s) from existing session '$($Session.ComputerName)'."
            }
        }
        else {
            Write-Verbose "Receiving file(s) from '$ComputerName'."
            
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

function Wait-SshComputer {
    <#
    .SYNOPSIS
        Waits for a remote computer to complete a potential restart and ensures the SSH session is working.
    
    .DESCRIPTION
        Acts as a checkpoint after running a command that might restart the remote computer.
        Monitors the connection during a grace period to detect if a shutdown occurs. If the
        server goes down, waits for it to come back online (with optional stability checking)
        and repairs the session in-place so the caller's variable remains usable.
        
        If the server never goes down during the grace period, the function returns quietly
        since the session is still healthy.
        
        The stability check is designed for scenarios like domain controller promotion where
        a server may restart multiple times. When -StableForSeconds is specified, the server
        must respond to connectivity tests continuously for that duration. If the server drops
        during the stability window, the timer resets and waiting continues.
        
        The session is repaired in-place using reflection, so no reassignment is needed. After
        this function returns, the caller's session variable is guaranteed to be working.
    
    .PARAMETER Session
        The existing PSSession to monitor. If a restart is detected, the session is repaired
        in-place so the caller's variable remains usable without reassignment.
    
    .PARAMETER Credential
        Optional PSCredential for repairing the session after a restart. If omitted, the
        credential stored on the session (from New-SshSession) is used automatically.
        If neither is available, key-based authentication is attempted using the username
        from the original session. When provided explicitly, this credential also replaces
        the stored credential on the session for future repairs.
    
    .PARAMETER ShutdownGracePeriodSeconds
        How long to monitor the connection for a shutdown. If the server has not stopped
        responding within this time, the function assumes no restart occurred and returns.
        This should always be long enough for the OS to begin shutting down. Defaults to 60.
    
    .PARAMETER WaitTimeoutSeconds
        Maximum total seconds to wait for the server to come back online after it goes down.
        This includes time spent in stability checks. Defaults to 600.
    
    .PARAMETER StableForSeconds
        How long the server must respond to connectivity tests continuously before it is
        considered truly online. If the server drops during this window, the timer resets.
        Use higher values (e.g. 120-300) for scenarios with multiple reboots like DC promotion.
        Defaults to 0 (first successful connection is sufficient).
    
    .PARAMETER PollIntervalSeconds
        How often to test connectivity while waiting. Defaults to 5.
    
    .PARAMETER Port
        SSH port. Defaults to the port from the original session, or 22 if not available.
    
    .EXAMPLE
        Invoke-Command -Session $session -ScriptBlock { Install-WindowsFeature AD-Domain-Services -Restart }
        Wait-SshComputer -Session $session -Credential $cred
        # $session is guaranteed working here, whether or not a restart occurred
    
    .EXAMPLE
        Invoke-SshCommand -Session $session -ScriptBlock { Install-ADDSForest -DomainName 'corp.local' -Force }
        Wait-SshComputer -Session $session -Credential $cred -ShutdownGracePeriodSeconds 120 -WaitTimeoutSeconds 900 -StableForSeconds 120
        # For DC promotion: gives 2 minutes for shutdown, waits up to 15 minutes, requires 2 minutes of stability
    
    .EXAMPLE
        Invoke-Command -Session $session -ScriptBlock { Start-Process 'setup.exe' -ArgumentList '/silent /restart' }
        Wait-SshComputer -Session $session -ShutdownGracePeriodSeconds 30 -StableForSeconds 30
        # Quick check with short grace period and stability requirement
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [int]$ShutdownGracePeriodSeconds = 60,

        [Parameter()]
        [int]$WaitTimeoutSeconds = 600,

        [Parameter()]
        [int]$StableForSeconds = 0,

        [Parameter()]
        [int]$PollIntervalSeconds = 5,

        [Parameter()]
        [int]$Port
    )

    # Extract connection info from the existing session
    $info = Get-SshSessionInfo -Session $Session
    $computerName = $info.ComputerName
    $userName = $info.UserName

    # Resolve credential: explicit parameter > stored on session
    if (-not $Credential -and $info.Credential) {
        $Credential = $info.Credential
        Write-Verbose "Using stored credential from session for '$computerName'."
    }

    if (-not $PSBoundParameters.ContainsKey('Port')) {
        $Port = $info.Port
    }

    Write-Verbose "Monitoring '$computerName' for potential restart (grace period: ${ShutdownGracePeriodSeconds}s)."

    # --- Phase 1: Watch for shutdown during grace period ---
    $testParams = @{
        ComputerName   = $computerName
        Port           = $Port
        TimeoutSeconds = [Math]::Min(10, $PollIntervalSeconds)
    }

    if ($Credential) {
        $testParams['Credential'] = $Credential
    }
    elseif ($userName) {
        $testParams['UserName'] = $userName
    }

    $graceDeadline = (Get-Date).AddSeconds($ShutdownGracePeriodSeconds)
    $serverWentDown = $false

    while ((Get-Date) -lt $graceDeadline) {
        if (-not (Test-SshConnection @testParams)) {
            $serverWentDown = $true
            Write-Verbose "Server '$computerName' is no longer responding. Restart detected."
            break
        }
        Write-Verbose "Server '$computerName' still responding, monitoring for shutdown..."
        Start-Sleep -Seconds $PollIntervalSeconds
    }

    if (-not $serverWentDown) {
        Write-Verbose "Server '$computerName' remained online during grace period. No restart detected."
        return
    }

    # --- Phase 2: Wait for the server to come back ---
    Write-Verbose "Waiting for '$computerName' to come back online (timeout: ${WaitTimeoutSeconds}s)."

    $waitDeadline = (Get-Date).AddSeconds($WaitTimeoutSeconds)
    $isOnline = $false
    $stableStart = $null

    while ((Get-Date) -lt $waitDeadline) {
        $reachable = Test-SshConnection @testParams

        if ($reachable) {
            if ($StableForSeconds -le 0) {
                $isOnline = $true
                Write-Verbose "Server '$computerName' is back online."
                break
            }

            if (-not $stableStart) {
                $stableStart = Get-Date
                Write-Verbose "Server '$computerName' responded. Starting stability check (${StableForSeconds}s required)."
            }

            $stableElapsed = ((Get-Date) - $stableStart).TotalSeconds
            if ($stableElapsed -ge $StableForSeconds) {
                $isOnline = $true
                Write-Verbose "Server '$computerName' has been stable for $([int]$stableElapsed) seconds. Stability check passed."
                break
            }

            $remaining = $StableForSeconds - [int]$stableElapsed
            Write-Verbose "Server '$computerName' up for $([int]$stableElapsed)s, need ${remaining}s more for stability."
        }
        else {
            if ($stableStart) {
                Write-Verbose "Server '$computerName' dropped during stability check. Resetting timer."
                $stableStart = $null
            }
        }

        Start-Sleep -Seconds $PollIntervalSeconds
    }

    if (-not $isOnline) {
        throw "Server '$computerName' did not come back online within $WaitTimeoutSeconds seconds."
    }

    # --- Phase 3: Repair the session in-place ---
    Write-Verbose "Repairing session to '$computerName' in-place."

    $newSessionParams = @{
        ComputerName = $computerName
        Port         = $Port
        SkipTest     = $true  # We already confirmed connectivity
    }

    if ($Credential) {
        $newSessionParams['Credential'] = $Credential
    }
    elseif ($userName) {
        $newSessionParams['UserName'] = $userName
    }

    $newSession = New-SshSession @newSessionParams
    Copy-SshSession -OldSession $Session -NewSession $newSession

    # Update stored credential if an explicit override was provided
    if ($PSBoundParameters.ContainsKey('Credential')) {
        $Session | Add-Member -NotePropertyName 'Credential' -NotePropertyValue $PSBoundParameters['Credential'] -Force
    }

    Write-Verbose "Session to '$computerName' repaired successfully."
}

function Restart-SshComputer {
    <#
    .SYNOPSIS
        Restarts a remote computer over SSH and waits for it to come back online.
    
    .DESCRIPTION
        Sends Restart-Computer -Force to the remote host via an existing PSSession, then uses
        Wait-SshComputer to wait for the server to go down, come back online, and optionally
        verify stability. The session is repaired in-place, so no reassignment is needed.
        
        The stability check is designed for scenarios like domain controller promotion where
        a server may restart multiple times. When -StableForSeconds is specified, the server
        must respond to connectivity tests continuously for that duration. If the server drops
        during the stability window, the timer resets and waiting continues.
    
    .PARAMETER Session
        The existing PSSession to the remote computer. This session will be used to send the
        restart command and will be repaired in-place after the restart completes.
    
    .PARAMETER Credential
        Optional PSCredential for repairing the session after restart. If omitted, the
        credential stored on the session (from New-SshSession) is used automatically.
        If neither is available, key-based authentication is used with the username from
        the original session.
    
    .PARAMETER ShutdownGracePeriodSeconds
        Maximum seconds to wait for the server to go down after sending the restart command.
        This should be long enough for the OS to begin shutting down. If the server has not
        stopped responding within this time, Wait-SshComputer assumes no restart occurred
        and returns. Defaults to 120.
    
    .PARAMETER WaitTimeoutSeconds
        Maximum total seconds to wait for the server to come back online after it goes down.
        This includes time spent in stability checks. Defaults to 600.
    
    .PARAMETER StableForSeconds
        How long the server must respond to connectivity tests continuously before it is
        considered truly online. If the server drops during this window, the timer resets.
        Use higher values (e.g. 120-300) for scenarios with multiple reboots like DC promotion.
        Defaults to 0 (first successful connection is sufficient).
    
    .PARAMETER PollIntervalSeconds
        How often to test connectivity while waiting. Defaults to 5.
    
    .PARAMETER Port
        SSH port. Defaults to the port from the original session, or 22 if not available.
    
    .EXAMPLE
        Restart-SshComputer -Session $session
        # Simple restart, waits for the server to come back. $session is repaired in-place.
    
    .EXAMPLE
        Restart-SshComputer -Session $session -Credential $cred
        # Restart with credential-based authentication. $session is repaired in-place.
    
    .EXAMPLE
        Restart-SshComputer -Session $session -Credential $cred -StableForSeconds 120 -WaitTimeoutSeconds 900
        # For DC promotion: waits up to 15 minutes, requires 2 minutes of continuous uptime.
    
    .EXAMPLE
        Restart-SshComputer -Session $session -StableForSeconds 60 -PollIntervalSeconds 10
        # Custom stability and polling intervals for a server that takes long to settle.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [System.Management.Automation.Runspaces.PSSession]$Session,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [int]$ShutdownGracePeriodSeconds = 120,

        [Parameter()]
        [int]$WaitTimeoutSeconds = 600,

        [Parameter()]
        [int]$StableForSeconds = 0,

        [Parameter()]
        [int]$PollIntervalSeconds = 5,

        [Parameter()]
        [int]$Port
    )

    $computerName = $Session.ComputerName

    # Resolve credential: explicit parameter > stored on session
    if (-not $Credential -and $Session.PSObject.Properties['Credential']) {
        $Credential = $Session.Credential
        Write-Verbose "Using stored credential from session for '$computerName'."
    }

    Write-Verbose "Restarting '$computerName'."

    # --- Send restart command ---
    Write-Verbose "Sending Restart-Computer -Force to '$computerName'."
    try {
        Invoke-Command -Session $Session -ScriptBlock { Restart-Computer -Force } -ErrorAction SilentlyContinue
    }
    catch {
        # Expected - the session will likely break as the server shuts down
        Write-Verbose "Restart command completed or session broke (expected): $_"
    }

    # Brief initial sleep to give the OS time to begin shutdown
    Start-Sleep -Seconds 5

    # --- Wait for restart and repair session in-place ---
    $waitParams = @{
        Session                    = $Session
        ShutdownGracePeriodSeconds = $ShutdownGracePeriodSeconds
        WaitTimeoutSeconds         = $WaitTimeoutSeconds
        StableForSeconds           = $StableForSeconds
        PollIntervalSeconds        = $PollIntervalSeconds
    }

    if ($Credential) {
        $waitParams['Credential'] = $Credential
    }

    if ($PSBoundParameters.ContainsKey('Port')) {
        $waitParams['Port'] = $Port
    }

    Wait-SshComputer @waitParams

    Write-Verbose "Restart of '$computerName' completed. Session is ready."
}

#endregion Public Functions

Export-ModuleMember -Function Test-SshConnection, New-SshSession, Invoke-SshCommand, Send-SshFile, Receive-SshFile, Wait-SshComputer, Restart-SshComputer