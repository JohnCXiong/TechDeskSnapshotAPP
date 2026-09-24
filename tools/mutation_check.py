"""Check that the tests really catch mistakes ("mutation testing").

This script copies the project to a temporary folder, then, one at a time,
makes a small deliberate mistake (a "mutant") in the copy and runs the whole
test suite. A good test suite fails for every mutant. If the tests still
pass, that mutant "survived" and shows a gap in the tests.

Your real project files are never changed. The temporary copy is deleted
at the end.

Run it from the project folder (it takes a few minutes):

    py tools\\mutation_check.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
PKG = "techdesk_snapshot/"

# (what the mistake does, file, exact original text, mistaken text)
MUTANTS = [
    ("a failed ping downgrades the network status", PKG + "checks.py",
     "    if data.gateway_ping is False:\n        notes.append(PING_NO_REPLY_NOTE)",
     "    if data.gateway_ping is False:\n        status = REVIEW\n        notes.append(PING_NO_REPLY_NOTE)"),
    ("a failed ping calls the gateway 'down'", PKG + "checks.py",
     "    if data.gateway_ping is False:\n        notes.append(PING_NO_REPLY_NOTE)",
     "    if data.gateway_ping is False:\n        summary += ' The default gateway is down.'\n        notes.append(PING_NO_REPLY_NOTE)"),
    ("virtual adapters count as a connection", PKG + "checks.py",
     "return data.physical_up == 0 and", "return data.adapters_up == 0 and"),
    ("an adapter read error is reported as offline", PKG + "checks.py",
     " and not data.gateway_found and not data.gateway_problem", " and not data.gateway_found"),
    ("the IP version of the HTTPS test is dropped", PKG + "checks.py",
     'tcp_family=tcp_family if tcp_family in ("IPv4", "IPv6") else None,', "tcp_family=None,"),
    ("more than 20 events are kept", PKG + "checks.py",
     "events = tuple(parsed[:MAX_EVENTS])", "events = tuple(parsed[:MAX_EVENTS + 1])"),
    ("events are sorted oldest first", PKG + "checks.py",
     "parsed.sort(key=lambda e: e.time, reverse=True)", "parsed.sort(key=lambda e: e.time)"),
    ("exactly 20 events are called incomplete", PKG + "checks.py",
     "len(parsed) > MAX_EVENTS", "len(parsed) >= MAX_EVENTS"),
    ("the event disclaimer is removed", PKG + "checks.py",
     "        notes.insert(0, EVENT_DISCLAIMER)\n", ""),
    ("an unreadable log with no errors shows OK", PKG + "checks.py",
     "    elif unreadable:\n        status = REVIEW", "    elif unreadable:\n        status = OK"),
    ("the 'under 10 GB' low-disk rule is removed", PKG + "checks.py",
     "return percent < LOW_DISK_PERCENT or self.free_gb < LOW_DISK_GB", "return percent < LOW_DISK_PERCENT"),
    ("PowerShell 5.1's value/Count list wrapper is not unwrapped", PKG + "checks.py",
     '    if isinstance(value, dict) and isinstance(value.get("value"), list) and "Count" in value:\n'
     '        return value["value"]\n', ""),
    ("'no matching events' is treated as an error", PKG + "checks.py",
     "        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }\n", ""),
    ("the event query goes back to -FilterHashtable", PKG + "checks.py",
     "$found = @(Get-WinEvent -LogName $logName -FilterXPath $xpath -MaxEvents $perLog -ErrorAction Stop)",
     "$found = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = 2 } -MaxEvents $perLog -ErrorAction Stop)"),
    ("Warning events are included", PKG + "checks.py", "(Level=2)", "(Level=3)"),
    ("event message text is exported", PKG + "checks.py",
     "                event_id = $e.Id\n", "                event_id = $e.Id\n                text = $e.Message\n"),
    ("every drive is listed, not just the system drive", PKG + "checks.py", "-Filter $diskFilter ", ""),
    ("the computer-name safety net is switched off", PKG + "ticket_note.py",
     "for value in sorted(names, key=len, reverse=True):", "for value in []:"),
    ("the real computer name and username are not looked up", PKG + "ticket_note.py",
     "    return sorted(v for v in values if v and len(v) >= 3)", "    return []"),
    ("the app's default identifiers are empty", PKG + "ticket_note.py",
     "names = list(local_identifiers() if identifiers is None else identifiers)", "names = list(identifiers or [])"),
    ("names are matched against the note's own sentences", PKG + "ticket_note.py",
     r'    return redact("\n".join(lines))', r'    return redact("\n".join(lines), names)'),
    ("generic names like 'User' are treated as private", PKG + "ticket_note.py",
     "    names = {v for v in names if v.lower() not in GENERIC_NAMES}\n", ""),
    ("IPv6 addresses are not redacted", PKG + "ticket_note.py",
     "    text = _IPV6_CANDIDATE.sub(_redact_ipv6, text)\n", "\n"),
    ("IPv4 is redacted before IPv6", PKG + "ticket_note.py",
     "    text = _IPV6_CANDIDATE.sub(_redact_ipv6, text)\n    text = _IPV4.sub(_redact_ipv4, text)",
     "    text = _IPV4.sub(_redact_ipv4, text)\n    text = _IPV6_CANDIDATE.sub(_redact_ipv6, text)"),
    ("an IPv6 address before a full stop is missed", PKG + "ticket_note.py",
     'while candidate.endswith("."):', "while False:"),
    ("versions like 4.0.0.0 are redacted", PKG + "ticket_note.py",
     "    if parts[1:] == [0, 0, 0]:\n        return text", "    if False:\n        return text"),
    ("the Windows version is not cleaned", PKG + "ticket_note.py",
     "{clean(data.windows) if data.windows else 'Not available'}", "{data.windows or 'Not available'}"),
    ("event sources are not cleaned", PKG + "ticket_note.py",
     "{clean(latest.provider)}, Event ID", "{latest.provider}, Event ID"),
    ("adapter names are copied into the note", PKG + "ticket_note.py",
     '        gateway = "Yes"', '        gateway = "Yes " + ", ".join(data.interface_aliases)'),
    ("raw failure text is copied into the note", PKG + "ticket_note.py",
     '    return ["- The check could not finish. Re-run it or collect this information manually."]',
     '    return ["- The check could not finish. " + result.summary]'),
    ("unreadable logs are reported as 'no errors'", PKG + "ticket_note.py",
     "    elif data.nothing_read:", "    elif False:"),
    ("ties in 'most frequent' go to the oldest event", PKG + "ticket_note.py",
     "-latest[item[0]].timestamp()", "latest[item[0]].timestamp()"),
    ("PowerShell runs through a shell", PKG + "powershell.py", "            shell=False,\n", "            shell=True,\n"),
    ("the execution policy is bypassed", PKG + "powershell.py",
     '        "-NonInteractive",\n', '        "-NonInteractive",\n        "-ep",\n        "Bypass",\n'),
    ("a console window flashes up for every check", PKG + "powershell.py", "            creationflags=NO_WINDOW,\n", ""),
    ("the timeout message always says 30 seconds", PKG + "powershell.py",
     "within {timeout:g} seconds", "within 30 seconds"),
    ("a timed-out PowerShell is left running", PKG + "powershell.py",
     "        process.kill()\n        process.communicate()\n        raise DiagnosticError(\n            f\"The check did not finish",
     "        raise DiagnosticError(\n            f\"The check did not finish"),
    ("locked-down PowerShell is blamed on permissions", PKG + "powershell.py",
     "if process.returncode == RESTRICTED_EXIT_CODE:", "if False:"),
    ("closing the window does not stop running checks", PKG + "powershell.py",
     "    for process in processes:", "    for process in []:"),
    ("a crash inside a check kills the background thread", PKG + "app.py",
     '        result = failed_result(title, f"Unexpected problem in the app: {type(exc).__name__}: {exc}")',
     "        raise"),
    ("re-running a check keeps its old result in the note", PKG + "app.py",
     "        self.results.pop(key, None)\n", ""),
    ("Copy Ticket Note copies the raw results", PKG + "app.py",
     "self.root.clipboard_append(note)", "self.root.clipboard_append(repr(self.results))"),
    ("Run All skips Recent Errors", PKG + "app.py",
     "        for key in CHECKS:\n            self.start_check(key, select_tab=False)",
     "        for key in ('pc', 'network'):\n            self.start_check(key, select_tab=False)"),
    ("the window can extend behind the taskbar", PKG + "app.py",
     "area_height - int(60 * scale)", "area_height"),
]


def run_tests(folder: Path) -> bool:
    """True if the whole test suite passes in this folder."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-q"],
            cwd=folder, capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def main() -> int:
    ignore = shutil.ignore_patterns("__pycache__", ".git", ".venv", "venv", "build", "dist")
    with tempfile.TemporaryDirectory(prefix="techdesk-mutants-") as temp:
        copy = Path(temp) / "project"
        shutil.copytree(PROJECT, copy, ignore=ignore)
        print("Running the normal test suite first...")
        if not run_tests(copy):
            print("The tests fail even without mutants. Fix that first.")
            return 1

        survived, broken = [], []
        for number, (what, file, original, mistake) in enumerate(MUTANTS, start=1):
            path = copy / file
            text = path.read_text(encoding="utf-8")
            if text.count(original) != 1:
                broken.append(what)
                print(f"{number:2}. {what}: SKIPPED (the code changed, so update this mutant)")
                continue
            path.write_text(text.replace(original, mistake), encoding="utf-8")
            caught = not run_tests(copy)
            path.write_text(text, encoding="utf-8")
            print(f"{number:2}. {what}: {'caught' if caught else 'SURVIVED'}", flush=True)
            if not caught:
                survived.append(what)

    caught_count = len(MUTANTS) - len(survived) - len(broken)
    print(f"\n{caught_count} of {len(MUTANTS)} mutants caught.")
    if survived:
        print("Survived (add a test for each):", *survived, sep="\n  - ")
    if broken:
        print("Skipped (their text no longer matches the code):", *broken, sep="\n  - ")
    return 0 if not survived and not broken else 1


if __name__ == "__main__":
    sys.exit(main())
