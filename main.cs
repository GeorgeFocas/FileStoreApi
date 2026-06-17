using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace NetworkShareHelpers;

public sealed record ShareAccessCredentials(
    string Domain,
    string Username,
    string Password);

public sealed class SecureNetworkFileCheckerOptions
{
    public int MaxAttempts { get; init; } = 3;
    public TimeSpan InitialDelay { get; init; } = TimeSpan.FromSeconds(2);
    public double BackoffFactor { get; init; } = 2.0;
    public bool RetryOnAccessDenied { get; init; } = false;
}

public enum PathCheckFailure
{
    None,
    NotFound,
    AccessDenied,
    NetworkUnavailable,
    InvalidPath,
    InvalidCredentials,
    Unknown
}

public sealed record PathCheckResult(
    bool Exists,
    int Attempts,
    PathCheckFailure Failure,
    string Message,
    Exception? Exception = null);

public sealed class SecureNetworkFileChecker
{
    private readonly SecureNetworkFileCheckerOptions _options;
    private readonly Random _jitter = new();

    public SecureNetworkFileChecker(SecureNetworkFileCheckerOptions? options = null)
    {
        _options = options ?? new SecureNetworkFileCheckerOptions();
    }

    public Task<PathCheckResult> FileExistsAsync(
        string uncPath,
        ShareAccessCredentials? credentials = null,
        CancellationToken cancellationToken = default)
        => CheckPathAsync(uncPath, expectDirectory: false, credentials, cancellationToken);

    public Task<PathCheckResult> DirectoryExistsAsync(
        string uncPath,
        ShareAccessCredentials? credentials = null,
        CancellationToken cancellationToken = default)
        => CheckPathAsync(uncPath, expectDirectory: true, credentials, cancellationToken);

    private async Task<PathCheckResult> CheckPathAsync(
        string uncPath,
        bool expectDirectory,
        ShareAccessCredentials? credentials,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(uncPath) || !uncPath.StartsWith(@"\\"))
        {
            return new PathCheckResult(
                Exists: false,
                Attempts: 0,
                Failure: PathCheckFailure.InvalidPath,
                Message: "Path must be a valid UNC path (e.g. \\\\server\\share\\file.txt).");
        }

        Exception? lastException = null;
        var delay = _options.InitialDelay;

        for (int attempt = 1; attempt <= _options.MaxAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                bool exists = credentials is null
                    ? CheckPathCore(uncPath, expectDirectory)
                    : RunImpersonated(credentials, () => CheckPathCore(uncPath, expectDirectory));

                return exists
                    ? new PathCheckResult(
                        Exists: true,
                        Attempts: attempt,
                        Failure: PathCheckFailure.None,
                        Message: expectDirectory ? "Directory exists." : "File exists.")
                    : new PathCheckResult(
                        Exists: false,
                        Attempts: attempt,
                        Failure: PathCheckFailure.NotFound,
                        Message: expectDirectory ? "Directory not found." : "File not found.");
            }
            catch (UnauthorizedAccessException ex)
            {
                lastException = ex;

                if (attempt < _options.MaxAttempts && _options.RetryOnAccessDenied)
                {
                    await DelayWithJitterAsync(delay, cancellationToken);
                    delay = NextDelay(delay);
                    continue;
                }

                return new PathCheckResult(
                    Exists: false,
                    Attempts: attempt,
                    Failure: PathCheckFailure.AccessDenied,
                    Message: "Access denied while checking the network path.",
                    Exception: ex);
            }
            catch (Win32Exception ex) when (IsInvalidCredentials(ex))
            {
                return new PathCheckResult(
                    Exists: false,
                    Attempts: attempt,
                    Failure: PathCheckFailure.InvalidCredentials,
                    Message: "The supplied credentials are invalid or not permitted for this resource.",
                    Exception: ex);
            }
            catch (Exception ex) when (IsTransient(ex))
            {
                lastException = ex;

                if (attempt < _options.MaxAttempts)
                {
                    await DelayWithJitterAsync(delay, cancellationToken);
                    delay = NextDelay(delay);
                    continue;
                }

                return new PathCheckResult(
                    Exists: false,
                    Attempts: attempt,
                    Failure: PathCheckFailure.NetworkUnavailable,
                    Message: "Transient network/share error while checking the path.",
                    Exception: ex);
            }
            catch (FileNotFoundException ex)
            {
                return new PathCheckResult(
                    Exists: false,
                    Attempts: attempt,
                    Failure: PathCheckFailure.NotFound,
                    Message: "File not found.",
                    Exception: ex);
            }
            catch (DirectoryNotFoundException ex)
            {
                return new PathCheckResult(
                    Exists: false,
                    Attempts: attempt,
                    Failure: PathCheckFailure.NotFound,
                    Message: "Directory not found.",
                    Exception: ex);
            }
            catch (Exception ex)
            {
                return new PathCheckResult(
                    Exists: false,
                    Attempts: attempt,
                    Failure: PathCheckFailure.Unknown,
                    Message: $"Unexpected error: {ex.Message}",
                    Exception: ex);
            }
        }

        return new PathCheckResult(
            Exists: false,
            Attempts: _options.MaxAttempts,
            Failure: PathCheckFailure.Unknown,
            Message: lastException?.Message ?? "Unknown failure.",
            Exception: lastException);
    }

    private static bool CheckPathCore(string path, bool expectDirectory)
    {
        var attributes = File.GetAttributes(path);
        bool isDirectory = (attributes & FileAttributes.Directory) == FileAttributes.Directory;

        return expectDirectory
            ? isDirectory
            : !isDirectory;
    }

    private static TimeSpan NextDelay(TimeSpan current) =>
        TimeSpan.FromMilliseconds(current.TotalMilliseconds <= 0
            ? 1000
            : current.TotalMilliseconds * 2);

    private async Task DelayWithJitterAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        int jitterMs = _jitter.Next(100, 400);
        await Task.Delay(delay + TimeSpan.FromMilliseconds(jitterMs), cancellationToken);
    }

    private static bool IsTransient(Exception ex)
    {
        if (ex is IOException)
            return true;

        if (ex is Win32Exception w32)
        {
            // Common transient network/share errors
            return w32.NativeErrorCode is
                53 or   // network path not found
                64 or   // network name no longer available
                67 or   // network name cannot be found
                121 or  // semaphore timeout
                1231 or // network location cannot be reached
                1232 or // network location cannot be reached
                1203;   // no network provider accepted the path
        }

        return false;
    }

    private static bool IsInvalidCredentials(Win32Exception ex)
    {
        return ex.NativeErrorCode is
            1326 or // username or password incorrect
            1385;   // logon failure: user not granted requested logon type
    }

    private static T RunImpersonated<T>(ShareAccessCredentials credentials, Func<T> action)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Credential-based impersonation is supported only on Windows.");

        bool ok = LogonUser(
            credentials.Username,
            credentials.Domain,
            credentials.Password,
            LOGON32_LOGON_NEW_CREDENTIALS,
            LOGON32_PROVIDER_DEFAULT,
            out SafeAccessTokenHandle token);

        if (!ok)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        using (token)
        {
            return WindowsIdentity.RunImpersonated(token, action);
        }
    }

    private const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
    private const int LOGON32_PROVIDER_DEFAULT = 0;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUser(
        string lpszUsername,
        string? lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out SafeAccessTokenHandle phToken);
}
