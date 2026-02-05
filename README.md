# SshSession

SshSession is a PowerShell module that simplifies using PowerShell Remoting over SSH. It provides a set of wrapper functions around the native `*-PSSession` and `*-Item` cmdlets to enable seamless, credential-based authentication and easier command execution and file transfers.

## Features

- **Simplified Credential Management**: Use `PSCredential` objects directly for password-based authentication, just like with WinRM-based remoting.
- **Persistent and Ephemeral Sessions**: Create and manage persistent `PSSession` objects or use one-liner commands for quick, ephemeral operations.
- **Familiar Syntax**: Works like native PowerShell Remoting (`*-PSSession`, `Invoke-Command`, `Copy-Item`).
- **File Transfer Support**: Easily send and receive files and directories to and from remote systems over SSH.
- **Cross-Platform**: Works on any platform that supports PowerShell and SSH.

## Getting Started

### Installation

1.  Clone or download this repository to a directory on your local machine.
2.  Import the module directly from the `.psm1` file:

    ```powershell
    Import-Module .\SshSession.psm1
    ```

3.  For persistent use, copy the `SshSession` directory to one of your PowerShell module paths (e.g., `$env:USERPROFILE\Documents\PowerShell\Modules`).
4.  Verify the module is available:

    ```powershell
    Get-Command -Module SshSession
    ```

## Usage

### `New-SshSession`

Creates a new persistent `PSSession` over SSH. This is ideal when you need to run multiple commands or transfer multiple files.

**Example 1: Create a session using a credential**

```powershell
$cred = Get-Credential
$session = New-SshSession -ComputerName 'server.example.com' -Credential $cred
$session
```

**Example 2: Create a session using key-based authentication**

If you have SSH key-based authentication configured, you can omit the `-Credential` parameter.

```powershell
$session = New-SshSession -ComputerName 'server.example.com' -UserName 'admin'
```

### `Invoke-SshCommand`

Executes a command on a remote host. It can use an existing session or create a temporary (ephemeral) one.

**Example 1: Invoke a command on an existing session**

```powershell
# Assumes $session was created with New-SshSession
Invoke-SshCommand -Session $session -ScriptBlock { Get-Process -Name 'sshd' }
```

**Example 2: Invoke a command using an ephemeral session**

```powershell
$cred = Get-Credential
Invoke-SshCommand -ComputerName 'server.example.com' -Credential $cred -ScriptBlock {
    Get-Service | Where-Object { $_.Status -eq 'Running' }
}
```

### `Send-SshFile`

Copies files or directories from your local machine to the remote host.

**Example 1: Copy a single file to an existing session**

```powershell
# Assumes $session was created with New-SshSession
Send-SshFile -Path '.\local-config.json' -Destination '/etc/myapp/config.json' -Session $session
```

**Example 2: Recursively copy a directory using an ephemeral session**

```powershell
$cred = Get-Credential
Send-SshFile -Path '.\scripts' -Destination '/opt/scripts' -ComputerName 'server.example.com' -Credential $cred -Recurse
```

### `Receive-SshFile`

Copies files or directories from the remote host to your local machine.

**Example 1: Receive a single log file**

```powershell
$cred = Get-Credential
Receive-SshFile -Path '/var/log/app.log' -Destination '.\logs\' -ComputerName 'server.example.com' -Credential $cred
```

**Example 2: Receive an entire directory from an existing session**

```powershell
# Assumes $session was created with New-SshSession
Receive-SshFile -Path '/etc/myapp' -Destination '.\backup' -Session $session -Recurse
```

## Credential Handling

This module simplifies password-based authentication with SSH by leveraging the `SSH_ASKPASS` environment variable. When you provide a `PSCredential` object, the module securely does the following:

1.  Sets the `SSH_ASKPASS` environment variable to point to a helper script (`ssh-askpass.cmd`).
2.  Stores the password from the `PSCredential` object in a temporary environment variable (`SSH_CREDENTIAL_PASSWORD`).
3.  The `ssh-askpass.cmd` script is called by `ssh.exe`, which then outputs the password.
4.  The temporary environment variables are automatically cleaned up after the session is created.

This allows `New-PSSession` to authenticate with a password without requiring interactive input, making it suitable for automation and scripting. Key-based authentication remains the default if no credential is provided.