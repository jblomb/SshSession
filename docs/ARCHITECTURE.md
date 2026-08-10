# SshSession architecture

This document describes how the module is organized and the behavioral contracts that are easy to miss when reading individual functions. It is intended for maintainers and reviewers. User-facing examples remain in the root [README](../README.md).

## Repository layout

| Path | Purpose |
|------|---------|
| `SshSession.psd1` | Module manifest, exported command list, version, metadata, and release notes. |
| `SshSession.psm1` | Private helpers, all exported functions, and the explicit `Export-ModuleMember` call. |
| `ssh-askpass.cmd` | Prints the temporary `SSH_CREDENTIAL_PASSWORD` value when OpenSSH requests a password. |
| `README.md` | Installation, examples, credential behavior, and known limitations. |

The public API is declared twice: in `FunctionsToExport` in the manifest and in `Export-ModuleMember` at the end of the module. Keep both lists synchronized.

## Public command map

| Command | Native operation | Connection lifetime | Repair behavior |
|---------|------------------|---------------------|-----------------|
| `Test-SshConnection` | Starts `ssh.exe` in a background job and runs an encoded `pwsh` command | One process per probe | None; returns a Boolean and writes a warning on failure. |
| `New-SshSession` | `New-PSSession -HostName` | Persistent | With `-Session`, creates and returns a replacement session; the caller must assign it. |
| `Invoke-SshCommand` | `Invoke-Command` | Existing or temporary | Repairs an existing session in place and retries one transport failure. |
| `Send-SshFile` | `Copy-Item -ToSession` | Existing or temporary | Repairs an existing session in place and retries one transport failure. |
| `Receive-SshFile` | `Copy-Item -FromSession` | Existing or temporary | Repairs an existing session in place and retries one transport failure. |
| `Wait-SshComputer` | Repeated `Test-SshConnection` probes | Existing | Repairs in place after an observed shutdown or when direct validation exposes a stale transport. |
| `Restart-SshComputer` | `Restart-Computer -Force`, then `Wait-SshComputer` | Existing | Delegates in-place repair to `Wait-SshComputer`. |
| `Enter-SshConsole` | Runs `ssh.exe` directly | Interactive process | None; a supplied session is only a source of connection details. |

## Connection modes

Most operation commands have two parameter sets:

- `ComputerName` mode creates a temporary session, performs the operation, and removes that session in a `finally` block.
- `Session` mode uses the supplied `PSSession`. Commands that execute or transfer data can repair it in place when credentials are available.

`New-SshSession` is different: its `Session` mode removes the old session and returns a new object. It does not perform the reflection-based in-place repair used by the operation commands. `Enter-SshConsole -Session` is also different: it reads the host, user, port, and stored credential, then starts an independent native SSH connection.

## Authentication flow

Key-based authentication is the default when no `PSCredential` is supplied. The optional username is passed to PowerShell remoting or included in the native SSH target.

Password authentication uses process-level environment variables:

1. `Set-SshAskpassEnvironment` saves the current values of the four SSH-related variables.
2. It points `SSH_ASKPASS` at `ssh-askpass.cmd`, forces askpass, and places the plaintext password in `SSH_CREDENTIAL_PASSWORD`.
3. The module starts `ssh.exe` directly or indirectly through `New-PSSession`.
4. A `finally` block calls `Remove-SshAskpassEnvironment`, which restores the previous values.

When a credential is used to create a persistent session, `New-SshSession` attaches it to the returned `PSSession` as a `Credential` note property. Credential selection during later repair is:

1. An explicitly supplied `-Credential`.
2. The `Credential` note property stored on the session.
3. No credential, which means the relevant code path uses the session username and relies on key-based authentication.

Because the askpass state is process-wide, overlapping password operations with different credentials are not isolated. See the README's known limitations before adding concurrency.

## Connectivity testing

The private `Invoke-SshProbe` helper runs encoded PowerShell commands through native SSH with a structured argument array inside a background job. The argument array prevents hostnames and usernames from being interpreted as executable PowerShell text. The outer timeout prevents the caller from waiting indefinitely. `Test-SshConnection` uses this helper with the success marker `OK!` and:

- returns `$true` only when the output contains the marker;
- returns `$false` for timeouts, SSH failures, authentication failures, and caught exceptions;
- writes failure details as warnings; and
- always removes its background job and restores askpass state.

When no port is explicitly supplied, the function omits `-p` so OpenSSH can resolve `Port` from its configuration or use its default of 22. Callers preserve this unspecified state rather than binding a default port before invoking the test.

`New-SshSession` calls this probe unless `-SkipTest` is present. The restart functions reuse it for state detection, so a successful probe means both native SSH command execution and remote `pwsh` are usable, not merely that an SSH TCP port is open. It does not validate the PowerShell SSH subsystem used by `New-PSSession`.

`Get-SshComputerUptime` uses the same helper to retrieve `[Environment]::TickCount64`. Keeping connectivity and uptime probes on the same native SSH path ensures they share credential, port, SSH-config, timeout, and cleanup behavior.

## Session repair and retry

In-place repair is implemented by `Repair-SshSession` and `Copy-SshSession`:

1. Extract connection details from the existing session.
2. Create a new session with `New-SshSession -Session`.
3. Copy the new session's non-public instance fields into the caller's existing object by reflection.
4. Restore the original `Id` and `Name` backing fields.
5. Copy the stored credential note property when present.

The caller's variable therefore continues to reference the same PowerShell object. Its underlying runspace has changed, and its computed `InstanceId` reflects the replacement runspace.

`Invoke-SshCommand`, `Send-SshFile`, and `Receive-SshFile` use the same two repair triggers:

- If `Session.State` is not `Opened`, repair before the operation when a credential is available.
- If an apparently open session throws `PSRemotingTransportException`, repair and retry the operation exactly once when a credential is available.

Other exception types are allowed to propagate. This distinction prevents an application error or invalid path from being treated as a stale transport. Do not broaden the catch without reviewing the retry semantics: remote commands and file operations are not guaranteed to be idempotent.

Reflection also means repaired sessions have special registry and lifecycle behavior. The limitations are documented in the README and should be rechecked when upgrading the supported PowerShell or .NET versions.

## Restart state machine

`Wait-SshComputer` has three phases:

1. **Shutdown detection:** probe until `ShutdownGracePeriodSeconds` expires. If the host stays reachable and the session remains open, validate the supplied session with a harmless remote command. Return when it succeeds; if it exposes a stale transport, skip the availability wait and continue directly to repair.
2. **Recovery and stability:** after an outage is observed, probe until `WaitTimeoutSeconds` expires. If `StableForSeconds` is nonzero, query `[Environment]::TickCount64` through remote `pwsh` and require the current OS boot to be at least that old. Failed SSH probes do not reset any client-side timer; an actual reboot resets the remote uptime naturally.
3. **Repair:** create a new session with the captured connection details and transplant it into the original session object.

`SshConnectionTimeoutSeconds` controls the timeout used by each connectivity probe in both the shutdown-detection and recovery phases.

`Restart-SshComputer` sends the restart request, tolerates the expected transport break, waits five seconds, and delegates the remaining state machine to `Wait-SshComputer`.

## Error and output contracts

- `Test-SshConnection` reports failure as `$false` plus a warning rather than throwing.
- `New-SshSession` throws when its preflight test returns `$false`.
- Command and transfer wrappers return the underlying PowerShell output and do not add a success object to the pipeline.
- Temporary sessions are removed even when an operation throws.
- `Wait-SshComputer` and `Restart-SshComputer` have no success output; they throw when the host does not return before the wait deadline.
- `Enter-SshConsole` is synchronous and returns after the native SSH process exits.

Preserving these output contracts matters in scripts that capture command results or use Boolean tests.

## Maintenance checklist

When changing the public API:

1. Update the function's comment-based help, including every parameter.
2. Update examples or parameter tables in `README.md`.
3. Keep `FunctionsToExport` and `Export-ModuleMember` synchronized.
4. Update the manifest version and release notes when preparing a release.
5. Import the manifest and run `Get-Help <command> -Full` to confirm help is attached to the intended function.

When changing connection or repair behavior, verify at least these scenarios manually or with mocks:

- credential and key-based session creation;
- cleanup after both success and failure;
- a visibly broken session;
- an `Opened` session with a dead transport;
- a non-transport remote error, which must not retry;
- no restart during the grace period;
- a single restart; and
- transient SSH failures while OS uptime continues increasing; and
- another OS restart during the stability window, which resets remote uptime.

The repository does not currently contain an automated test suite, so this list is the minimum regression baseline until tests are added.
