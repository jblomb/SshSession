@{
    RootModule        = 'SshSession.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3f7e8d2-5b4c-4a1f-9e6d-8c2b3a4f5e6d'
    Author            = 'Blomman'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2025. All rights reserved.'
    Description       = 'Enables PSCredential-based authentication for SSH remoting in PowerShell 7. Wraps New-PSSession, Invoke-Command, and Copy-Item with SSH_ASKPASS support.'
    PowerShellVersion = '7.0'
    
    FunctionsToExport = @(
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
            ReleaseNotes = 'Initial release. Provides credential-based SSH session management for PowerShell 7.'
        }
    }
}