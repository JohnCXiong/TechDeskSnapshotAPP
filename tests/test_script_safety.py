"""Guardrail tests: the PowerShell scripts must stay read-only and private.

These tests read the script text. If someone later adds a command that
changes the PC, contacts other computers, or collects names or message
text, a test fails.
"""

import re
import unittest

from techdesk_snapshot.checks import EVENTS_SCRIPT, NETWORK_SCRIPT, PC_HEALTH_SCRIPT
from techdesk_snapshot.powershell import SCRIPT_PREAMBLE

SCRIPTS = {
    "preamble": SCRIPT_PREAMBLE,
    "pc_health": PC_HEALTH_SCRIPT,
    "network": NETWORK_SCRIPT,
    "events": EVENTS_SCRIPT,
}

# Commands that change something, start other programs or download things.
FORBIDDEN_COMMANDS = [
    r"\bSet-(?!StrictMode)\w+",  # Set-ItemProperty, Set-ExecutionPolicy, Set-NetIPAddress ...
    r"\bRemove-\w+",
    r"\bClear-\w+",  # Clear-EventLog, Clear-DnsClientCache ...
    r"\bNew-Item\b",
    r"\bNew-ItemProperty\b",
    r"\bStop-\w+",
    r"\bRestart-\w+",
    r"\bDisable-\w+",
    r"\bEnable-\w+",
    r"\bStart-Process\b",
    r"\bInvoke-(?:Expression|WebRequest|RestMethod|Command|CimMethod|WmiMethod)\b",
    r"\biex\b",
    r"\bOut-File\b",
    r"\bAdd-Content\b",
    r"\bExport-\w+",
    r"\bRegister-\w+",
    r"\bnetsh\b",
    r"\breg(?:\.exe)?\s+(?:add|delete)\b",
    r"-Verb\s+RunAs",
    r"\bExecutionPolicy\b",
]

# Things that would identify a person or computer, or collect message text.
FORBIDDEN_DATA = [
    r"\bCSName\b",
    r"\bUserName\b",
    r"\bMachineName\b",
    r"\bWin32_UserAccount\b",
    r"\$env:(?:COMPUTERNAME|USERNAME|USERDOMAIN)\b",
    r"\$e\.Message\b",
    r"\bFormatDescription\b",
    r"-ComputerName\b",  # never query or scan other computers
    r"\bCredential\b",
]


class ScriptSafetyTests(unittest.TestCase):
    def test_scripts_do_not_change_anything(self):
        for name, script in SCRIPTS.items():
            for pattern in FORBIDDEN_COMMANDS:
                with self.subTest(script=name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, script, re.IGNORECASE))

    def test_scripts_do_not_collect_identities_or_message_text(self):
        for name, script in SCRIPTS.items():
            for pattern in FORBIDDEN_DATA:
                with self.subTest(script=name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, script, re.IGNORECASE))

    def test_scripts_contain_no_double_quotes(self):
        # The script is passed as a command-line argument. Using only single
        # quotes means Windows never has to escape anything, so PowerShell
        # receives exactly the text written here.
        for name, script in SCRIPTS.items():
            with self.subTest(script=name):
                self.assertNotIn('"', script)

    def test_every_check_prints_json(self):
        for name in ("pc_health", "network", "events"):
            with self.subTest(script=name):
                self.assertIn("ConvertTo-TechDeskJson", SCRIPTS[name])

    def test_event_script_asks_only_for_error_level_in_two_local_logs(self):
        self.assertIn("$days = 7", EVENTS_SCRIPT)
        self.assertIn("$perLog = 20", EVENTS_SCRIPT)
        self.assertIn("foreach ($logName in @('System', 'Application'))", EVENTS_SCRIPT)
        self.assertIn(
            "$xpath = '*[System[(Level=2) and TimeCreated[timediff(@SystemTime) <= ' + ($days * 86400000) + ']]]'",
            EVENTS_SCRIPT,
        )
        self.assertIn(
            "Get-WinEvent -LogName $logName -FilterXPath $xpath -MaxEvents $perLog -ErrorAction Stop",
            EVENTS_SCRIPT,
        )

    def test_event_script_treats_no_matching_events_as_an_empty_log(self):
        # Get-WinEvent throws when nothing matches. Without this line, a PC
        # with a clean log would show "Could not check".
        self.assertIn("if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }", EVENTS_SCRIPT)

    def test_event_script_does_not_use_filterhashtable(self):
        # -FilterHashtable reports a log you may not read as "no events found",
        # which would hide a permission problem behind a clean-looking result.
        # (The script's comments may mention it; its code must not.)
        code = [line for line in EVENTS_SCRIPT.splitlines() if not line.strip().startswith("#")]
        self.assertNotIn("FilterHashtable", "\n".join(code))

    def test_network_script_does_not_count_virtual_adapters_as_a_connection(self):
        self.assertIn("$result.physical_up = @($upAdapters | Where-Object { -not $_.Virtual }).Count", NETWORK_SCRIPT)

    def test_network_script_uses_ipv6_only_when_that_is_the_only_way_out(self):
        self.assertIn(
            "if (($hasIPv6Route -and -not $hasIPv4Route -and $ipv6.Count -gt 0) -or $ipv4.Count -eq 0) {",
            NETWORK_SCRIPT,
        )

    def test_pc_health_asks_only_for_the_system_drive(self):
        self.assertIn("-Filter $diskFilter", PC_HEALTH_SCRIPT)
        self.assertIn("$diskFilter = 'DeviceID=''' + $env:SystemDrive + ''''", PC_HEALTH_SCRIPT)

    def test_network_script_only_contacts_example_com_and_the_gateway(self):
        self.assertIn("-Name 'example.com'", NETWORK_SCRIPT)
        self.assertIn("ConnectAsync($ip, 443)", NETWORK_SCRIPT)
        self.assertEqual(NETWORK_SCRIPT.count(".Send("), 1)  # the single ping call: the gateway
        # No hard-coded addresses. 0.0.0.0 only appears as "the default route".
        addresses = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", NETWORK_SCRIPT))
        self.assertEqual(addresses, {"0.0.0.0"})


if __name__ == "__main__":
    unittest.main()
