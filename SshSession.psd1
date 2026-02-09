@{
    RootModule        = 'SshSession.psm1'
    ModuleVersion     = '1.5.0'
    GUID              = 'a3f7e8d2-5b4c-4a1f-9e6d-8c2b3a4f5e6d'
    Author            = 'Blomman'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2025. All rights reserved.'
    Description       = 'Enables PSCredential-based authentication for SSH remoting in PowerShell 7. Wraps New-PSSession, Invoke-Command, and Copy-Item with SSH_ASKPASS support. Includes connectivity testing with timeout protection.'
    PowerShellVersion = '7.0'
    
    FunctionsToExport = @(
        'Test-SshConnection'
        'New-SshSession'
        'Invoke-SshCommand'
        'Send-SshFile'
        'Receive-SshFile'
        'Restart-SshComputer'
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