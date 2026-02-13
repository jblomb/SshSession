@{
    RootModule        = 'SshSession.psm1'
    ModuleVersion     = '1.8.0'
    GUID              = 'a3f7e8d2-5b4c-4a1f-9e6d-8c2b3a4f5e6d'
    Author            = 'Blomman'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2025. All rights reserved.'
    Description       = 'Enables PSCredential-based authentication for SSH remoting in PowerShell 7. Wraps New-PSSession, Invoke-Command, and Copy-Item with SSH_ASKPASS support. Includes connectivity testing with timeout protection, interactive SSH console for full terminal support, and credentials stored on session objects for automatic repair.'
    PowerShellVersion = '7.0'
    
    FunctionsToExport = @(
        'Test-SshConnection'
        'New-SshSession'
        'Invoke-SshCommand'
        'Send-SshFile'
        'Receive-SshFile'
        'Wait-SshComputer'
        'Restart-SshComputer'
        'Enter-SshConsole'
    )
    
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    
    PrivateData       = @{
        PSData = @{
            Tags         = @('SSH', 'Remoting', 'PSSession', 'Credential', 'Authentication')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = @'
1.8.0
- Added Enter-SshConsole for interactive SSH console sessions using ssh.exe directly
- Provides a proper terminal that supports interactive programs (edit.exe, vi, top, etc.)
- Defaults to pwsh as remote shell to match PSSession behavior
- Shows [hostname]: PS path> prompt for pwsh/powershell shells, matching Enter-PSSession
- Supports -Shell parameter to select remote shell: pwsh, powershell, cmd, bash, or Default
- Accepts the same connection parameters as New-SshSession (ComputerName, Credential, UserName, Port, Options)
- Supports -Session parameter to extract connection details from an existing PSSession
- Uses SSH_ASKPASS for credential-based authentication, consistent with the rest of the module

1.7.0
- Credential is now stored on the PSSession object as a NoteProperty when created with New-SshSession -Credential
- All functions that accept -Session automatically use the stored credential for repair when no explicit -Credential is provided
- Explicit -Credential always takes priority over the stored credential (supports credential changes after reboot)
- Explicit -Credential updates the stored credential on the session for future repairs
- Copy-SshSession preserves the stored credential when transplanting session internals
- Wait-SshComputer and Restart-SshComputer no longer require -Credential if the session was created with one

1.6.0
- Added Wait-SshComputer for waiting on potential restarts and repairing sessions in-place
- Monitors a shutdown grace period to detect if the server goes down, then waits for online with optional stability check
- Session is repaired in-place via reflection when a restart is detected, no reassignment needed
- Refactored Restart-SshComputer to use Wait-SshComputer internally, now repairs in-place (no return value)
- Restart-SshComputer now uses ShutdownGracePeriodSeconds instead of RestartTimeoutSeconds (breaking change)

1.5.0
- In-place session repair for Invoke-SshCommand, Send-SshFile, and Receive-SshFile
- When a broken session is repaired, the caller's variable is updated in-place via reflection
- No longer requires reassigning the session variable after repair in these functions
- Added private Copy-SshSession helper for reflection-based session transplant
- New-SshSession -Session and Restart-SshComputer still return new session objects (unchanged)

1.4.0
- Added -Session parameter to New-SshSession for repairing broken/disconnected sessions
- Added -Session with -Credential support to Invoke-SshCommand, Send-SshFile, and Receive-SshFile
- Restart-SshComputer now uses New-SshSession -Session internally for session replacement
- Added private Get-SshSessionInfo helper for extracting connection details from existing sessions

1.3.0
- Added Restart-SshComputer for restarting remote servers and returning a new session
- Supports stability checks for multi-reboot scenarios (e.g. DC promotion)
- Configurable timeouts for shutdown detection, wait-for-online, and stability duration

1.2.0
- Fixed credential auth falling back to key-based auth
- New-SshSession now forces password-only auth when credentials are provided
- Test-SshConnection also forces password-only auth with credentials

1.1.0
- Added Test-SshConnection for connectivity testing with timeout protection
- New-SshSession now tests connectivity by default (use -SkipTest to bypass)
- Added -TestTimeoutSeconds parameter to New-SshSession
- Refactored SSH_ASKPASS handling into private helper functions

1.0.0
- Initial release. Provides credential-based SSH session management for PowerShell 7.
'@
        }
    }
}