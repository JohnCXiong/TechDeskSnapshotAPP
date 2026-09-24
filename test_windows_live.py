"""Live tests: run the real, read-only PowerShell scripts on this Windows PC.

They check that the scripts work with the real Windows PowerShell 5.1 and
return data the parsers accept. They check the shape of the results, not
the values, because every PC is different. On macOS or Linux they are
skipped.

Like the app, they make one DNS lookup and one HTTPS connection to
example.com, and ping the default gateway.
"""

import ctypes
import sys
import unittest
from datetime import timedelta

from techdesk_snapshot import checks
from techdesk_snapshot.checks import FAILED, OK, now_local, parse_events, parse_network, parse_pc_health
from techdesk_snapshot.powershell import run_powershell_json


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


@unittest.skipUnless(sys.platform == "win32", "live Windows PowerShell tests only run on Windows")
class LiveScriptTests(unittest.TestCase):
    def test_pc_health_script(self):
        raw = run_powershell_json(checks.PC_HEALTH_SCRIPT, timeout=checks.PC_HEALTH_TIMEOUT)
        result = parse_pc_health(raw, now_local())
        self.assertNotEqual(result.status, FAILED, result.summary)
        self.assertIn("Windows", result.data.windows)
        self.assertGreater(result.data.ram_gb, 0)
        self.assertGreater(result.data.total_gb, 0)

    def test_network_script_returns_every_field(self):
        raw = run_powershell_json(checks.NETWORK_SCRIPT, timeout=checks.NETWORK_TIMEOUT)
        for key in ("adapters_up", "physical_up", "gateway_found", "dns_ok", "tcp_ok", "gateway_ping"):
            self.assertIn(key, raw)
        result = parse_network(raw, now_local())
        self.assertNotEqual(result.status, FAILED, result.summary)
        self.assertNotIn("gateway_address", raw)  # the gateway address never leaves PowerShell

    def test_events_script(self):
        started = now_local()
        raw = run_powershell_json(checks.EVENTS_SCRIPT, timeout=checks.EVENTS_TIMEOUT)
        result = parse_events(raw, started)
        self.assertNotEqual(result.status, FAILED, result.summary)
        self.assertLessEqual(len(result.data.events), 20)
        for item in raw["events"]:
            self.assertEqual(set(item), {"time", "log", "provider", "event_id"})  # no message text
        for record in result.data.events:
            self.assertIn(record.log, ("System", "Application"))
            self.assertGreaterEqual(record.time, started - timedelta(days=7, minutes=5))

    def test_empty_time_window_is_reported_as_no_events(self):
        # $days = 0 matches nothing, so Get-WinEvent says "no matching events".
        script = checks.EVENTS_SCRIPT.replace("$days = 7", "$days = 0")
        raw = run_powershell_json(script, timeout=checks.EVENTS_TIMEOUT)
        self.assertEqual(raw["log_errors"], [])
        self.assertEqual(parse_events(raw, now_local()).status, OK)

    @unittest.skipIf(is_admin(), "the Security log is readable when running as administrator")
    def test_a_log_you_may_not_read_is_reported_as_access_denied(self):
        # The Security log needs admin rights. It must show up as a permission
        # problem, not as "no events".
        script = checks.EVENTS_SCRIPT.replace("@('System', 'Application')", "@('Security')")
        raw = run_powershell_json(script, timeout=checks.EVENTS_TIMEOUT)
        self.assertEqual([(e["log"], e["kind"]) for e in raw["log_errors"]], [("Security", "access_denied")])


if __name__ == "__main__":
    unittest.main()
