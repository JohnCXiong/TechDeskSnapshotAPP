"""Tests for error handling: timeouts, missing PowerShell, permissions, bad output.

subprocess.Popen is replaced with a fake, so these tests never start
PowerShell and do not depend on the PC they run on.
"""

import subprocess
import unittest
from unittest import mock

from techdesk_snapshot import checks, powershell
from techdesk_snapshot.checks import FAILED, run_network_check, run_pc_health, run_recent_errors
from techdesk_snapshot.powershell import (
    NO_WINDOW,
    PERMISSION_MESSAGE,
    RESTRICTED_EXIT_CODE,
    RESTRICTED_MESSAGE,
    SCRIPT_PREAMBLE,
    DiagnosticError,
    build_command,
    parse_json_output,
    powershell_path,
    run_powershell_json,
    stop_running_checks,
)


class FakeProcess:
    """Stands in for a running powershell.exe."""

    def __init__(self, stdout=b"", stderr=b"", returncode=0, hang=False):
        self.stdout_data = stdout
        self.stderr_data = stderr
        self.returncode = returncode
        self.hang = hang
        self.killed = False

    def communicate(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired(cmd="powershell.exe", timeout=timeout)
        return self.stdout_data, self.stderr_data

    def kill(self):
        self.killed = True


@mock.patch.object(powershell, "is_windows", return_value=True)
class RunPowerShellTests(unittest.TestCase):
    def run_with(self, process_or_error, timeout=30):
        with mock.patch.object(powershell.subprocess, "Popen", side_effect=[process_or_error]) as popen:
            result = run_powershell_json("Write-Output 1", timeout=timeout)
        return result, popen

    def assert_fails_with(self, process_or_error, timeout=30):
        with self.assertRaises(DiagnosticError) as ctx:
            self.run_with(process_or_error, timeout)
        return str(ctx.exception)

    def test_success_returns_parsed_json_and_uses_safe_options(self, _):
        process = FakeProcess(b'{"ok": true}\r\n')
        result, popen = self.run_with(process)
        self.assertEqual(result, {"ok": True})
        kwargs = popen.call_args.kwargs
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], subprocess.PIPE)
        self.assertEqual(kwargs["creationflags"], NO_WINDOW)
        self.assertEqual(popen.call_args.args[0], build_command("Write-Output 1"))
        self.assertEqual(powershell._running, set(), "finished processes must not stay tracked")

    def test_timeout_stops_the_process_and_gives_a_friendly_message(self, _):
        process = FakeProcess(hang=True)
        message = self.assert_fails_with(process, timeout=45)
        self.assertIn("did not finish within 45 seconds", message)
        self.assertTrue(process.killed)
        self.assertEqual(powershell._running, set())

    def test_missing_powershell(self, _):
        message = self.assert_fails_with(FileNotFoundError(2, "The system cannot find the file specified"))
        self.assertIn("Windows PowerShell was not found", message)

    def test_blocked_from_starting(self, _):
        message = self.assert_fails_with(PermissionError(13, "Access is denied"))
        self.assertIn("could not be started", message)

    def test_access_denied_error_output(self, _):
        stderr = b"Get-CimInstance : Access denied \r\n    + CategoryInfo : PermissionDenied: (root\\cimv2) [Get-CimInstance]\r\n"
        message = self.assert_fails_with(FakeProcess(stderr=stderr, returncode=1))
        self.assertEqual(message, PERMISSION_MESSAGE)

    def test_constrained_language_mode_is_explained_not_blamed_on_permissions(self, _):
        stderr = b"New-Object : Cannot create type. Only core types are supported in this language mode.\r\n PermissionDenied"
        message = self.assert_fails_with(FakeProcess(stderr=stderr, returncode=RESTRICTED_EXIT_CODE))
        self.assertEqual(message, RESTRICTED_MESSAGE)

    def test_other_error_output_shows_the_first_useful_line(self, _):
        stderr = (
            b"Get-CimInstance : Invalid class \r\nAt line:4 char:1\r\n"
            b"+ Get-CimInstance -ClassName Win32_Nope\r\n+ ~~~~~~~~~~~~~\r\n"
        )
        message = self.assert_fails_with(FakeProcess(stderr=stderr, returncode=1))
        self.assertIn("exit code 1", message)
        self.assertIn("Get-CimInstance : Invalid class", message)
        self.assertNotIn("At line", message)

    def test_error_with_no_explanation(self, _):
        self.assertIn("exit code 5", self.assert_fails_with(FakeProcess(returncode=5)))

    def test_clixml_error_output_is_made_readable(self, _):
        stderr = (
            b'#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">'
            b'<S S="Error">Something broke_x000D__x000A_</S></Objs>'
        )
        message = self.assert_fails_with(FakeProcess(stderr=stderr, returncode=1))
        self.assertIn("Something broke", message)
        self.assertNotIn("CLIXML", message)

    def test_empty_output(self, _):
        self.assertIn("did not return any results", self.assert_fails_with(FakeProcess(b"  \r\n")))

    def test_non_json_output(self, _):
        message = self.assert_fails_with(FakeProcess(b"Caption : Microsoft Windows 11 Pro\r\n"))
        self.assertIn("unexpected format", message)


@mock.patch.object(powershell, "is_windows", return_value=True)
class StopRunningChecksTests(unittest.TestCase):
    def setUp(self):
        # stop_running_checks() sets a module-level flag; put it back after each test.
        patcher = mock.patch.object(powershell, "_stopping", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_closing_the_window_stops_running_powershell(self, _):
        running = FakeProcess()
        already_gone = mock.Mock(kill=mock.Mock(side_effect=ProcessLookupError()))
        with mock.patch.object(powershell, "_running", {running, already_gone}):
            stop_running_checks()
        self.assertTrue(running.killed)

    def test_no_new_check_starts_after_the_window_closed(self, _):
        stop_running_checks()
        with mock.patch.object(powershell.subprocess, "Popen") as popen:
            with self.assertRaises(DiagnosticError) as ctx:
                run_powershell_json("Write-Output 1", timeout=5)
        popen.assert_not_called()
        self.assertIn("window was closed", str(ctx.exception))

    def test_check_starting_while_the_window_closes_is_stopped(self, _):
        process = FakeProcess(b'{"ok": true}')

        def start_while_closing(*args, **kwargs):
            stop_running_checks()  # the window closes while PowerShell is starting
            return process

        with mock.patch.object(powershell.subprocess, "Popen", side_effect=start_while_closing):
            with self.assertRaises(DiagnosticError):
                run_powershell_json("Write-Output 1", timeout=5)
        self.assertTrue(process.killed)
        self.assertEqual(powershell._running, set())


class NonWindowsTests(unittest.TestCase):
    def test_refuses_to_run_off_windows(self):
        with mock.patch.object(powershell, "is_windows", return_value=False), \
                mock.patch.object(powershell.subprocess, "Popen") as popen:
            with self.assertRaises(DiagnosticError) as ctx:
                run_powershell_json("Write-Output 1", timeout=5)
        popen.assert_not_called()
        self.assertIn("only works on Windows", str(ctx.exception))


class ParseJsonOutputTests(unittest.TestCase):
    def test_extra_lines_before_the_json(self):
        self.assertEqual(parse_json_output('Some notice\r\n{"a": 1}\r\n'), {"a": 1})

    def test_non_english_letters_sent_as_escape_codes(self):
        # The PowerShell side sends "Microsoft Windows 11 Professionnel é" like this:
        self.assertEqual(parse_json_output('{"s": "Professionnel \\u00e9"}'), {"s": "Professionnel é"})


class CommandLineTests(unittest.TestCase):
    def test_command_is_exactly_the_fixed_safe_command(self):
        # Pinning the whole list also rules out abbreviations such as "-ep Bypass".
        self.assertEqual(
            build_command("Get-Date"),
            [powershell_path(), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", SCRIPT_PREAMBLE + "Get-Date"],
        )

    def test_powershell_is_started_by_full_path(self):
        with mock.patch.dict("os.environ", {"SystemRoot": r"C:\Windows"}):
            self.assertEqual(powershell_path(), r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")

    def test_scripts_stop_early_in_constrained_language_mode(self):
        first_line = SCRIPT_PREAMBLE.strip().splitlines()[0]
        self.assertIn("LanguageMode -ne 'FullLanguage'", first_line)
        self.assertIn(f"exit {RESTRICTED_EXIT_CODE}", first_line)


class ChecksNeverCrashTests(unittest.TestCase):
    """Each run_* function must turn any failure into a "Could not check" result."""

    def test_diagnostic_errors_become_failed_results(self):
        with mock.patch.object(checks, "run_powershell_json", side_effect=DiagnosticError("timed out")):
            for run in (run_pc_health, run_network_check, run_recent_errors):
                with self.subTest(check=run.__name__):
                    result = run()
                    self.assertEqual(result.status, FAILED)
                    self.assertEqual(result.summary, "timed out")
                    self.assertIsNone(result.data)
                    self.assertIsNotNone(result.checked_at.tzinfo)

    def test_unexpected_json_shape_becomes_a_failed_result(self):
        with mock.patch.object(checks, "run_powershell_json", return_value=[1, 2, 3]):
            self.assertEqual(run_pc_health().status, FAILED)

    def test_each_check_runs_its_own_script_with_its_own_timeout(self):
        cases = (
            (run_pc_health, checks.PC_HEALTH_SCRIPT, checks.PC_HEALTH_TIMEOUT),
            (run_network_check, checks.NETWORK_SCRIPT, checks.NETWORK_TIMEOUT),
            (run_recent_errors, checks.EVENTS_SCRIPT, checks.EVENTS_TIMEOUT),
        )
        for run, script, timeout in cases:
            with self.subTest(check=run.__name__):
                with mock.patch.object(checks, "run_powershell_json", side_effect=DiagnosticError("x")) as fake:
                    run()
                self.assertIs(fake.call_args.args[0], script)
                self.assertEqual(fake.call_args.kwargs["timeout"], timeout)


class WindowWorkerTests(unittest.TestCase):
    """The background worker must report a crash as a result, not kill the thread silently."""

    def test_unexpected_exception_is_reported(self):
        try:
            from techdesk_snapshot.app import run_in_background
        except ImportError:  # tkinter missing (some Linux installs)
            self.skipTest("tkinter is not available")
        import queue

        results = queue.Queue()

        def broken_check():
            raise RuntimeError("bug in a parser")

        run_in_background(results, "pc", "PC Health", broken_check)
        key, result = results.get_nowait()
        self.assertEqual(key, "pc")
        self.assertEqual(result.status, FAILED)
        self.assertIn("bug in a parser", result.summary)


if __name__ == "__main__":
    unittest.main()
