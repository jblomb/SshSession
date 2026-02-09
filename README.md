# SshSession

SshSession is a PowerShell module that simplifies using PowerShell Remoting over SSH. It provides a set of wrapper functions around the native `*-PSSession` and `*-Item` cmdlets to enable seamless, credential-based authentication and easier command execution and file transfers.

## Features

- **Simplified Credential Management**: Use `PSCredential` objects directly for password-based authentication, just like with WinRM-based remoting.
- **Connection Testing with Timeout**: Automatically tests connectivity before creating sessions to avoid hanging on unreachable hosts.
- **Session Repair**: Pass an existing broken or disconnected `PSSession` to any function to automatically replace it with a fresh session using the same connection details.
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

### `Test-SshConnection`

Tests SSH connectivity to a remote host with timeout protection. Returns `$true` if the connection succeeds, `$false` otherwise. Use `-Verbose` to see detailed failure information.

**Example 1: Test connectivity before running commands**

```powershell
if (Test-SshConnection -ComputerName 'server.example.com' -Credential $cred) {
    # Proceed with operations
}
```

**Example 2: Test with a shorter timeout**

```powershell
Test-SshConnection -ComputerName 'server.example.com' -TimeoutSeconds 10 -Verbose
```

### `New-SshSession`

Creates a new persistent `PSSession` over SSH. This is ideal when you need to run multiple commands or transfer multiple files.

By default, `New-SshSession` tests connectivity before creating the session to avoid hanging on unreachable hosts. Use `-SkipTest` to bypass this check.

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

**Example 3: Skip the connectivity test**

```powershell
$session = New-SshSession -ComputerName 'server.example.com' -Credential $cred -SkipTest
```

**Example 4: Use a custom timeout for the connectivity test**

```powershell
$session = New-SshSession -ComputerName 'server.example.com' -Credential $cred -TestTimeoutSeconds 10
```

**Example 5: Repair a broken session**

If a session is broken or disconnected, pass it to `-Session` to create a fresh replacement with the same connection details. The old session is removed automatically.

```powershell
$session = New-SshSession -Session $session -Credential $cred
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

**Example 3: Repair a broken session and invoke a command**

```powershell
Invoke-SshCommand -Session $session -Credential $cred -ScriptBlock { Get-Process }
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

**Example 3: Repair a broken session and send files**

```powershell
Send-SshFile -Path '.\config.json' -Destination '/etc/myapp/' -Session $session -Credential $cred
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

**Example 3: Repair a broken session and receive files**

```powershell
Receive-SshFile -Path '/var/log/app.log' -Destination '.\logs\' -Session $session -Credential $cred
```

### `Restart-SshComputer`

Restarts a remote computer, waits for it to come back online, and returns a new session. The old session is automatically removed. Supports a stability check for scenarios where the server may restart multiple times (e.g. domain controller promotion).

**Example 1: Simple restart**

```powershell
$session = Restart-SshComputer -Session $session
```

**Example 2: Restart with credentials**

Since credentials cannot be extracted from an existing `PSSession`, pass them explicitly if the session uses password authentication.

```powershell
$session = Restart-SshComputer -Session $session -Credential $cred
```

**Example 3: Domain controller promotion (multiple reboots)**

Wait up to 15 minutes for the server to come back, and require it to stay up for 2 minutes continuously before considering it stable.

```powershell
$session = Restart-SshComputer -Session $session -Credential $cred -StableForSeconds 120 -WaitTimeoutSeconds 900
```

**Example 4: Custom polling interval**

```powershell
$session = Restart-SshComputer -Session $session -PollIntervalSeconds 10 -Verbose
```

| Parameter | Description |
|-----------|-------------|
| `-Session` | The existing `PSSession` to restart. Will be removed after the restart. |
| `-Credential` | Optional credential for the new session. Required if the original session used password auth. |
| `-RestartTimeoutSeconds` | Max seconds to wait for the server to go down (default: 120). |
| `-WaitTimeoutSeconds` | Max total seconds to wait for the server to come back (default: 600). |
| `-StableForSeconds` | How long the server must stay up continuously before it's considered online (default: 0). |
| `-PollIntervalSeconds` | How often to check connectivity (default: 5). |
| `-Port` | SSH port. Defaults to the port from the original session. |

## Common Parameters

The following parameters are available on `New-SshSession`, `Invoke-SshCommand`, `Send-SshFile`, and `Receive-SshFile` when creating ephemeral sessions:

| Parameter | Description |
|-----------|-------------|
| `-SkipTest` | Skip the connectivity test before creating the session. Use when you're confident the host is reachable or when the test overhead is undesirable. |
| `-TestTimeoutSeconds` | Timeout for the connectivity test in seconds. Defaults to 30. Ignored if `-SkipTest` is specified. |

## Session Repair

All functions that accept a `-Session` parameter also support session repair. When you pass `-Session` together with `-Credential`, the function will create a fresh replacement session using the connection details from the old session. This is useful when a session has broken due to a network interruption, timeout, or server restart.

For `Invoke-SshCommand`, `Send-SshFile`, and `Receive-SshFile`, the repair happens **in-place** — the caller's `$session` variable is updated transparently via reflection so it remains usable after the operation completes. No reassignment is needed.

```powershell
# Session broke after a reboot? These just work — $session is repaired in-place:
Invoke-SshCommand -Session $session -Credential $cred -ScriptBlock { Get-Date }
Send-SshFile -Path .\file.txt -Destination /tmp/ -Session $session -Credential $cred
Receive-SshFile -Path /tmp/file.txt -Destination .\ -Session $session -Credential $cred

# $session is now working again — no reassignment needed!
Invoke-SshCommand -Session $session -ScriptBlock { hostname }
```

For `New-SshSession` and `Restart-SshComputer`, a new session object is returned (assign it back to your variable):

```powershell
$session = New-SshSession -Session $session -Credential $cred
$session = Restart-SshComputer -Session $session -Credential $cred
```

**Note on `Get-PSSession`**: The in-place repair uses reflection to transplant connection internals into the existing PSSession object. As a side effect, the repaired session will not appear in `Get-PSSession` output (the session registry still tracks the original entry). The session works correctly through the caller's variable, and all objects are cleaned up when the PowerShell process exits.

## Credential Handling

This module simplifies password-based authentication with SSH by leveraging the `SSH_ASKPASS` environment variable. When you provide a `PSCredential` object, the module securely does the following:

1.  Sets the `SSH_ASKPASS` environment variable to point to a helper script (`ssh-askpass.cmd`).
2.  Stores the password from the `PSCredential` object in a temporary environment variable (`SSH_CREDENTIAL_PASSWORD`).
3.  The `ssh-askpass.cmd` script is called by `ssh.exe`, which then outputs the password.
4.  The temporary environment variables are automatically cleaned up after the session is created.

This allows `New-PSSession` to authenticate with a password without requiring interactive input, making it suitable for automation and scripting. Key-based authentication remains the default if no credential is provided.

When credentials are provided, the module forces password-only authentication (`PreferredAuthentications=password`, `PubkeyAuthentication=no`) to prevent SSH from falling back to key-based authentication if the password is incorrect.