@{
    RootModule        = 'SshSession.psm1'
    ModuleVersion     = '1.2.0'
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