"""Run fixed, read-only Windows PowerShell scripts and return their JSON output.

Every check in this app works the same way:

1. Python starts Windows PowerShell with a fixed script written in checks.py.
2. The script collects a few facts and prints them as one line of JSON.
3. Python parses that JSON. It never reads the formatted text you would see
   in a console window, because that text changes between Windows versions
   and languages.

Safety rules applied here:

* ``shell=False``: Python starts powershell.exe directly. No command prompt
  sits in between, so nothing in the script can be treated as a shell command.
* The full path to powershell.exe is used, so a look-alike program earlier in
  PATH cannot be started by mistake.
* The execution policy is never touched. It controls ``.ps1`` script files,
  and this app passes its commands with ``-Command`` instead.
* ``-NoProfile`` skips the user's PowerShell profile, so every run is the same.
* ``-NonInteractive`` stops PowerShell from waiting for input that will never
  come.
"""

from __future__ import annotations

import json
import ntpath
import os
import re
import subprocess
import sys
import threading
from typing import Any

# On Windows this keeps a black console window from flashing up each time a
# check runs. The value is 0 on other systems, where the flag does not exist.
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# The scripts exit with this code when PowerShell runs in Constrained
# Language Mode. Some security policies (AppLocker or WDAC) turn that mode on.
RESTRICTED_EXIT_CODE = 42

# Added to the start of every script.
#
# * The first line checks for Constrained Language Mode. In that mode the
#   scripts cannot work, so they stop at once with a clear exit code
#   instead of failing halfway through.
# * Hiding progress bars and warnings stops PowerShell from writing extra
#   text into the output.
# * UTF-8 output keeps error messages readable on non-English Windows. This
#   only affects the hidden PowerShell process that is started for the check.
# * ConvertTo-TechDeskJson turns the result into one line of JSON. It also
#   writes any non-English letters as \\uXXXX codes, so the output is plain
#   ASCII whatever the console's code page is. json.loads in Python turns the
#   codes back into the original letters.
# * Get-ErrorKind reports "access_denied" for permission errors. It checks
#   the error type, not the message text, which is translated on non-English
#   Windows.
SCRIPT_PREAMBLE = r"""
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { exit 42 }
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function ConvertTo-TechDeskJson {
    param($InputObject)
    $json = ConvertTo-Json -InputObject $InputObject -Depth 5 -Compress
    [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
}

function Get-ErrorKind {
    param($ErrorRecord)
    $ex = $ErrorRecord.Exception
    if ($ex -is [System.UnauthorizedAccessException]) { return 'access_denied' }
    if ($ex.HResult -eq -2147024891) { return 'access_denied' }
    if ($ErrorRecord.CategoryInfo.Category -eq 'PermissionDenied') { return 'access_denied' }
    return 'other'
}
"""

PERMISSION_MESSAGE = (
    "Windows would not let this check read the information with your current "
    "permissions. TechDesk Snapshot never asks for administrator rights. Note this "
    "on the ticket and ask an administrator if the information is needed."
)

RESTRICTED_MESSAGE = (
    "PowerShell on this PC is restricted by a security policy (Constrained Language "
    "Mode), so TechDesk Snapshot cannot run its checks here. Do not try to get around "
    "the policy. Note it on the ticket and collect the information manually."
)

_PERMISSION_HINTS = (
    "access is denied",
    "access denied",
    "unauthorizedaccess",
    "permissiondenied",
    "unauthorized operation",
)


class DiagnosticError(Exception):
    """A check could not finish. The message is written for the technician."""


# PowerShell processes that are running right now. The window stops them
# when it closes, so nothing is left running in the background. After that,
# _stopping is True and no new check may start.
_running: set[subprocess.Popen] = set()
_running_lock = threading.Lock()
_stopping = False


def is_windows() -> bool:
    return sys.platform == "win32"


def powershell_path() -> str:
    """Full path to the Windows PowerShell 5.1 that ships with Windows 10 and 11."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    # ntpath always joins with backslashes, even when the tests run on macOS or Linux.
    return ntpath.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def build_command(script: str) -> list[str]:
    """The exact argument list passed to subprocess.Popen (shell=False, so no shell is involved)."""
    return [
        powershell_path(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        SCRIPT_PREAMBLE + script,
    ]


def run_powershell_json(script: str, *, timeout: float) -> Any:
    """Run one fixed script and return its parsed JSON output.

    Raises DiagnosticError with a plain-English message when something goes
    wrong, so the window can show it instead of crashing.
    """
    if not is_windows():
        raise DiagnosticError(
            "TechDesk Snapshot runs its checks with Windows PowerShell, so it only "
            "works on Windows 10 or Windows 11."
        )

    with _running_lock:
        if _stopping:
            raise DiagnosticError("The window was closed, so the check was not started.")
    try:
        process = subprocess.Popen(
            build_command(script),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=NO_WINDOW,
        )
    except FileNotFoundError:
        raise DiagnosticError(
            f"Windows PowerShell was not found at {powershell_path()}. "
            "It is built into Windows 10 and 11, so this PC may have it removed or blocked."
        ) from None
    except OSError as exc:
        raise DiagnosticError(
            f"Windows PowerShell could not be started ({exc.strerror or exc}). "
            "Security software or a policy may be blocking it."
        ) from None

    with _running_lock:
        closed_meanwhile = _stopping  # the window closed while PowerShell was starting
        if not closed_meanwhile:
            _running.add(process)
    if closed_meanwhile:
        process.kill()
        process.communicate()
        raise DiagnosticError("The window was closed, so the check was stopped.")
    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise DiagnosticError(
            f"The check did not finish within {timeout:g} seconds, so it was stopped. "
            "The PC may be very busy, or a network request is hanging. Try again in a minute."
        ) from None
    finally:
        with _running_lock:
            _running.discard(process)

    if process.returncode == RESTRICTED_EXIT_CODE:
        raise DiagnosticError(RESTRICTED_MESSAGE)
    if process.returncode != 0:
        raise DiagnosticError(explain_powershell_failure(_decode(stderr_bytes), process.returncode))

    return parse_json_output(_decode(stdout_bytes))


def stop_running_checks() -> None:
    """Stop any PowerShell process that is still running, and start no new ones.

    Used when the window closes.
    """
    global _stopping
    with _running_lock:
        _stopping = True
        processes = list(_running)
    for process in processes:
        try:
            process.kill()
        except OSError:
            pass  # it already finished


def parse_json_output(stdout: str) -> Any:
    """Parse the single JSON line a script prints.

    If something else printed extra lines, the last line that looks like
    JSON is used.
    """
    text = stdout.strip()
    if not text:
        raise DiagnosticError("PowerShell finished but did not return any results. Try running the check again.")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith(("{", "[")):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                break
    raise DiagnosticError(
        "PowerShell returned results in an unexpected format, so they could not be read. "
        "Try running the check again."
    )


def explain_powershell_failure(stderr: str, returncode: int) -> str:
    """Turn PowerShell's error output into one short, readable sentence."""
    lowered = stderr.lower()
    if any(hint in lowered for hint in _PERMISSION_HINTS):
        return PERMISSION_MESSAGE
    first_line = _first_error_line(stderr)
    if first_line:
        return f"PowerShell reported an error (exit code {returncode}): {first_line}"
    return f"PowerShell stopped with exit code {returncode} and did not explain why. Try running the check again."


def _first_error_line(stderr: str) -> str:
    """The first meaningful line of PowerShell error text, shortened to fit the window."""
    # When the caller is another PowerShell, errors can arrive as CLIXML.
    # Pull the readable text out of it.
    if stderr.lstrip().startswith("#< CLIXML"):
        parts = re.findall(r'<S S="Error">(.*?)</S>', stderr, flags=re.DOTALL)
        stderr = "".join(parts).replace("_x000D__x000A_", "\n")
    for line in stderr.splitlines():
        line = line.strip()
        if line and not line.startswith(("At line:", "+", "~")):
            return line if len(line) <= 200 else line[:197] + "..."
    return ""


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    return data.decode("utf-8-sig", errors="replace")
