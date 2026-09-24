"""Tests for the copied ticket note: content, next checks and redaction.

The fake identifiers below stand in for a real computer name, username and
domain. They are planted in places they could leak from, and the tests
check that they never reach the note.
"""

import re
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

from techdesk_snapshot.checks import (
    GIB,
    failed_result,
    parse_events,
    parse_network,
    parse_pc_health,
)
from techdesk_snapshot.ticket_note import (
    REDACTED,
    build_ticket_note,
    format_timestamp,
    local_identifiers,
    redact,
    suggest_next_checks,
    top_event_groups,
)
from tests.test_parsing import CHECKED_AT, event, network_sample, pc_sample

FAKE_IDS = ["DESKTOP-TEST01", "jdoe", "CONTOSO"]
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def note_for(pc=None, network=None, events=None):
    return build_ticket_note(pc=pc, network=network, events=events, identifiers=FAKE_IDS)


def events_result(items, log_errors=None):
    return parse_events({"days": 7, "per_log_limit": 20, "events": items, "log_errors": log_errors or []}, CHECKED_AT)


class TicketNoteContentTests(unittest.TestCase):
    def test_full_note_has_time_results_and_next_checks(self):
        note = note_for(
            parse_pc_health(pc_sample(), CHECKED_AT),
            parse_network(network_sample(), CHECKED_AT),
            events_result([event("2026-09-23T09:15:00-07:00")]),
        )
        self.assertIn("Checks run: 2026-09-24 14:32 (UTC-07:00)", note)
        self.assertIn("PC HEALTH - OK (checked 14:32)", note)
        self.assertIn("- Windows: Microsoft Windows 11 Pro, version 24H2 (build 26100.4652), 64-bit", note)
        self.assertIn("- Installed RAM: 16 GB", note)
        self.assertIn("- System drive (C:): 120.0 GB free of 476.0 GB (25% free)", note)
        self.assertIn("- DNS lookup of example.com: OK", note)
        self.assertIn("- HTTPS connection (TCP 443) to example.com: OK", note)
        self.assertIn("Service Control Manager, Event ID 7000", note)
        self.assertIn("does not prove what caused a problem", note)
        self.assertIn("SUGGESTED NEXT CHECKS", note)
        self.assertIn("Confirm the exact symptom", note)
        self.assertNotIn(REDACTED, note, "A normal note should not need any redaction")

    def test_checks_not_run_are_marked(self):
        note = note_for(pc=parse_pc_health(pc_sample(), CHECKED_AT))
        self.assertIn("NETWORK CHECK - Not run", note)
        self.assertIn("RECENT ERRORS - Not run", note)

    def test_time_range_when_checks_ran_at_different_times(self):
        later = CHECKED_AT + timedelta(minutes=5)
        note = note_for(
            parse_pc_health(pc_sample(), CHECKED_AT),
            parse_network(network_sample(), later),
        )
        self.assertIn("Checks run: 2026-09-24 14:32 (UTC-07:00) to 2026-09-24 14:37 (UTC-07:00)", note)

    def test_failed_ping_is_described_as_not_proof_of_an_outage(self):
        note = note_for(network=parse_network(network_sample(gateway_ping=False), CHECKED_AT))
        self.assertIn("NETWORK CHECK - OK", note)
        self.assertIn(
            "- Gateway ping: No reply (for information only: many routers ignore ping, "
            "so this is not proof of an outage)\n",
            note,
        )
        # No network "next check" is suggested when DNS and HTTPS both worked.
        self.assertNotIn("ipconfig", note)
        self.assertNotIn("nslookup", note)

    def test_https_line_names_the_ip_version(self):
        note = note_for(network=parse_network(network_sample(tcp_family="IPv6"), CHECKED_AT))
        self.assertIn("- HTTPS connection (TCP 443) to example.com: OK over IPv6", note)

    def test_unreadable_log_is_listed_with_advice(self):
        note = note_for(events=events_result(
            [], log_errors=[{"log": "Application", "kind": "access_denied", "message": "denied"}]
        ))
        self.assertIn("- Could not read: Application log", note)
        self.assertIn("Ask an administrator", note)

    def test_most_frequent_events_are_grouped(self):
        items = [event(f"2026-09-23T10:0{i}:00-07:00") for i in range(4)]
        items.append(event("2026-09-23T11:00:00-07:00", log="Application", provider="Application Error", event_id=1000))
        note = note_for(events=events_result(items))
        self.assertIn("5 Error events in the last 7 days (Application: 1, System: 4)", note)
        self.assertIn("- Most recent: 2026-09-23 11:00, Application, Application Error, Event ID 1000", note)
        self.assertIn("    Service Control Manager, Event ID 7000: 4", note)
        self.assertIn("Service Control Manager Event ID 7000 appears 4 times. Look it up", note)

    def test_a_single_event_gets_no_repeat_hint(self):
        note = note_for(events=events_result([event("2026-09-23T09:15:00-07:00")]))
        self.assertNotIn("appears", note)

    def test_more_than_20_events_are_described_as_a_sample(self):
        items = [event(f"2026-09-23T10:{i:02d}:00-07:00") for i in range(20)]
        items.append(event("2026-09-23T11:00:00-07:00", log="Application", provider="Application Error", event_id=1000))
        note = note_for(events=events_result(items))
        self.assertIn(
            "- The 20 most recent Error events from the last 7 days (more may exist). Among these: Application: 1, System: 19",
            note,
        )
        self.assertIn("Service Control Manager Event ID 7000 appears 19 times among the 20 most recent errors", note)

    def test_no_events(self):
        note = note_for(events=events_result([]))
        self.assertIn("RECENT ERRORS - OK", note)
        self.assertIn("No Error events found in the last 7 days", note)

    def test_unreadable_logs_are_never_reported_as_no_errors(self):
        both = note_for(events=events_result([], log_errors=[
            {"log": "System", "kind": "access_denied", "message": "denied"},
            {"log": "Application", "kind": "access_denied", "message": "denied"},
        ]))
        self.assertIn("RECENT ERRORS - Could not check", both)
        self.assertIn("- No log could be read, so recent errors are unknown.", both)
        self.assertNotIn("No Error events found", both)

        one = note_for(events=events_result([], log_errors=[
            {"log": "Application", "kind": "access_denied", "message": "denied"},
        ]))
        self.assertIn("- No Error events found in the logs that could be read (last 7 days).", one)
        self.assertNotIn("No Error events found in the last", one)

    def test_permission_advice_only_for_permission_errors(self):
        service_down = note_for(events=events_result([], log_errors=[
            {"log": "System", "kind": "other", "message": "The RPC server is unavailable"},
        ]))
        self.assertNotIn("administrator", service_down)
        self.assertIn("Re-run Recent Errors", service_down)
        self.assertNotIn("RPC server", service_down)  # raw error text stays out of the note

    def test_pc_health_that_read_nothing_suggests_a_manual_check(self):
        pc = parse_pc_health({"errors": [{"part": "windows", "kind": "other", "message": "WMI is broken"}]}, CHECKED_AT)
        note = note_for(pc=pc)
        self.assertIn("PC HEALTH - Could not check", note)
        self.assertIn("Re-run PC Health, or check Settings > System > About and Storage manually.", note)


class NextCheckTests(unittest.TestCase):
    def suggestions(self, **network_overrides):
        net = parse_network(network_sample(**network_overrides), CHECKED_AT)
        return " ".join(suggest_next_checks(None, net, None))

    def test_offline(self):
        text = self.suggestions(
            adapters_up=0, physical_up=0, gateway_found=False, gateway_ping=None, dns_ok=False, tcp_ok=None
        )
        self.assertIn("airplane mode", text)

    def test_offline_with_virtual_adapters_up(self):
        text = self.suggestions(
            adapters_up=2, physical_up=0, gateway_found=False, gateway_ping=None, dns_ok=False, tcp_ok=None
        )
        self.assertIn("airplane mode", text)
        self.assertNotIn("DHCP", text)

    def test_no_gateway(self):
        text = self.suggestions(gateway_found=False, gateway_ping=None, dns_ok=False, tcp_ok=None)
        self.assertIn("ipconfig /all", text)

    def test_dns_failure(self):
        text = self.suggestions(dns_ok=False, dns_error_code=9003, tcp_ok=None)
        self.assertIn("nslookup example.com", text)

    def test_https_failure(self):
        text = self.suggestions(tcp_ok=False, tcp_error="TimedOut")
        self.assertIn("proxy", text)

    def test_low_disk_and_windows_10(self):
        pc = parse_pc_health(
            pc_sample(os_caption="Microsoft Windows 10 Pro", os_build="19045", drive_free_bytes=2 * GIB),
            CHECKED_AT,
        )
        text = " ".join(suggest_next_checks(pc, None, None))
        self.assertIn("Storage", text)
        self.assertIn("Extended Security Updates", text)

    def test_failed_checks_suggest_a_manual_fallback(self):
        items = suggest_next_checks(
            failed_result("PC Health", "boom", CHECKED_AT),
            failed_result("Network Check", "boom", CHECKED_AT),
            failed_result("Recent Errors", "boom", CHECKED_AT),
        )
        text = " ".join(items)
        self.assertIn("Re-run PC Health", text)
        self.assertIn("Test-NetConnection", text)
        self.assertIn("Event Viewer", text)

    def test_list_is_kept_short(self):
        pc = parse_pc_health(
            pc_sample(os_caption="Microsoft Windows 10 Pro", os_build="19045", drive_free_bytes=2 * GIB),
            CHECKED_AT,
        )
        net = parse_network(network_sample(dns_ok=False, tcp_ok=None), CHECKED_AT)
        ev = events_result(
            [event(f"2026-09-23T10:0{i}:00-07:00") for i in range(5)],
            log_errors=[{"log": "Application", "kind": "access_denied", "message": "denied"}],
        )
        self.assertLessEqual(len(suggest_next_checks(pc, net, ev)), 6)


class TicketNoteRedactionTests(unittest.TestCase):
    def test_private_details_planted_in_results_never_reach_the_note(self):
        pc = parse_pc_health(pc_sample(os_caption="Microsoft Windows 11 Pro on DESKTOP-TEST01"), CHECKED_AT)
        net = parse_network(
            network_sample(
                interface_aliases=["jdoe's home Wi-Fi"],
                dns_ok=False,
                dns_error="Server 192.168.1.1 on CONTOSO refused the query",
                dns_error_code=None,
                tcp_ok=None,
            ),
            CHECKED_AT,
        )
        ev = events_result([
            event("2026-09-23T09:15:00-07:00", provider="Backup agent for jdoe", message="Logon failure for CONTOSO\\jdoe from 10.1.2.3"),
        ])
        note = note_for(pc, net, ev)

        for secret in FAKE_IDS:
            self.assertNotRegex(note, re.compile(re.escape(secret), re.IGNORECASE))
        self.assertIsNone(IPV4_PATTERN.search(note), note)
        self.assertNotIn("home Wi-Fi", note)  # adapter names stay in the window only
        self.assertNotIn("Logon failure", note)  # event message text is never collected
        self.assertNotIn("refused the query", note)  # raw error text is never copied
        self.assertIn("Backup agent for " + REDACTED, note)  # the safety net caught the planted username

    def test_real_computer_name_and_username_are_read_from_windows(self):
        # This is the path the app really uses: no identifiers passed in.
        fake_env = {
            "COMPUTERNAME": "PC-FAKE01",
            "USERNAME": "fakeuser",
            "USERDOMAIN": "FAKEDOM",
            "USERPROFILE": r"C:\Users\fakeuser.FAKEDOM",
        }
        with mock.patch.dict("os.environ", fake_env), \
                mock.patch("socket.gethostname", side_effect=OSError), \
                mock.patch("getpass.getuser", return_value="fakeuser"):
            self.assertLessEqual({"PC-FAKE01", "fakeuser", "FAKEDOM", "fakeuser.FAKEDOM"}, set(local_identifiers()))
            pc = parse_pc_health(pc_sample(os_caption="Microsoft Windows 11 Pro (PC-FAKE01)"), CHECKED_AT)
            ev = events_result([event("2026-09-23T09:15:00-07:00", provider="Sync for FAKEDOM\\fakeuser")])
            note = build_ticket_note(pc=pc, events=ev)
        for secret in ("PC-FAKE01", "fakeuser", "FAKEDOM"):
            self.assertNotIn(secret.lower(), note.lower())

    def test_generic_account_names_do_not_damage_the_note(self):
        # PCs with an account literally named "User", "Test" or "Administrator" are common.
        pc = parse_pc_health(pc_sample(drive_free_bytes=2 * GIB), CHECKED_AT)
        failed_net = failed_result("Network Check", "boom", CHECKED_AT)
        ev = events_result(
            [event("2026-09-23T09:15:00-07:00", provider="Microsoft-Windows-User Profiles Service", event_id=1500),
             event("2026-09-23T09:16:00-07:00", provider="Service Control Manager")],
            log_errors=[{"log": "System", "kind": "access_denied", "message": "denied"}],
        )
        for names in (["User"], ["Test"], ["Administrator"], ["Service"], ["SERVER"]):
            with self.subTest(identifiers=names):
                note = build_ticket_note(pc=pc, network=failed_net, events=ev, identifiers=names)
                self.assertNotIn(REDACTED, note)
                self.assertIn("with the user before removing anything", note)
                self.assertIn("Test-NetConnection example.com -Port 443", note)
                self.assertIn("Ask an administrator", note)
                self.assertIn("Microsoft-Windows-User Profiles Service", note)
                self.assertIn("Service Control Manager", note)

    def test_the_notes_own_sentences_are_never_matched_against_names(self):
        # Even a name that is not in the generic list (a PC called "STORAGE" or
        # "EXAMPLE") must not damage the app's fixed wording, only values from Windows.
        pc = parse_pc_health(pc_sample(drive_free_bytes=2 * GIB), CHECKED_AT)
        net = parse_network(network_sample(dns_ok=False, dns_error_code=9003, tcp_ok=None), CHECKED_AT)
        note = build_ticket_note(pc=pc, network=net, identifiers=["STORAGE", "EXAMPLE"])
        self.assertNotIn(REDACTED, note)
        self.assertIn("Review Settings > System > Storage with the user", note)
        self.assertIn("Run nslookup example.com", note)

    def test_failure_messages_are_not_copied(self):
        failed = failed_result(
            "PC Health",
            r"PowerShell reported an error: C:\Users\jdoe\Documents\x.ps1 on \\fileserver01\share",
            CHECKED_AT,
        )
        note = note_for(pc=failed)
        self.assertIn("PC HEALTH - Could not check", note)
        self.assertNotIn("jdoe", note)
        self.assertNotIn("fileserver01", note)
        self.assertNotIn("PowerShell reported", note)


class RedactFunctionTests(unittest.TestCase):
    def test_ipv4_addresses(self):
        self.assertEqual(redact("gateway 192.168.1.1."), f"gateway {REDACTED}.")
        self.assertEqual(redact("10.0.0.5, 8.8.8.8"), f"{REDACTED}, {REDACTED}")
        self.assertEqual(redact("dns 192.168.001.010"), f"dns {REDACTED}")  # leading zeros

    def test_ipv6_addresses(self):
        for address in ("2001:db8::8a2e:370:7334", "fe80::1c2b:3a4d:5e6f:7a8b%12", "::1",
                        "2001:0db8:0000:0000:0000:ff00:0042:8329", "::ffff:192.0.2.128"):
            with self.subTest(address=address):
                self.assertEqual(redact(f"addr {address} end"), f"addr {REDACTED} end")
        self.assertEqual(redact("gateway 2001:db8::1."), f"gateway {REDACTED}.")
        self.assertEqual(redact("via fe80::1%12."), f"via {REDACTED}.")

    def test_mac_email_and_paths(self):
        self.assertEqual(redact("mac 00-1A-2B-3C-4D-5E"), f"mac {REDACTED}")
        self.assertEqual(redact("mac 00:1a:2b:3c:4d:5e"), f"mac {REDACTED}")
        self.assertEqual(redact("mail j.doe@contoso.com now"), f"mail {REDACTED} now")
        self.assertEqual(redact("mail jsmith@localhost now"), f"mail {REDACTED} now")
        self.assertEqual(redact(r"C:\Users\Jane Doe\AppData\x.log"), "C:\\Users\\" + REDACTED + r"\AppData\x.log")
        self.assertEqual(redact("C:/Users/jsmith/AppData"), f"C:/Users/{REDACTED}/AppData")
        self.assertEqual(redact(r"see \\fileserver01\share"), "see \\\\" + REDACTED + r"\share")

    def test_versioned_event_sources_are_kept(self):
        # Real .NET event sources end in a version that looks like an address.
        for source in ("System.ServiceModel 4.0.0.0, Event ID 3", "SMSvcHost 3.0.0.0", "ASP.NET 2.0.50727.0"):
            with self.subTest(source=source):
                self.assertEqual(redact(source), source)

    def test_things_that_only_look_similar_are_kept(self):
        for safe in (
            "build 26100.4652",
            "version 10.0.26100.4652",
            "10.0.19045",
            "checked 14:32:05",
            "2026-09-24 14:32 (UTC-07:00)",
            "Event ID 10010: 4",
            "120.0 GB free of 476.0 GB (25% free)",
        ):
            with self.subTest(text=safe):
                self.assertEqual(redact(safe), safe)

    def test_identifiers_are_whole_word_and_case_insensitive(self):
        self.assertEqual(redact("user JDOE logged on", ["jdoe"]), f"user {REDACTED} logged on")
        self.assertEqual(redact("jdoesmith", ["jdoe"]), "jdoesmith")
        self.assertEqual(redact("pc DESKTOP-TEST01.", ["DESKTOP-TEST01"]), f"pc {REDACTED}.")
        self.assertEqual(redact("Backup_jdoe", ["jdoe"]), f"Backup_{REDACTED}")

    def test_generic_names_are_not_treated_as_identifiers(self):
        self.assertEqual(redact("ask the user", ["User"]), "ask the user")

    def test_very_short_identifiers_are_ignored(self):
        # A two-letter value would remove ordinary words like "OK" or "ID".
        self.assertEqual(redact("OK ID 7000", ["ok", "id"]), "OK ID 7000")

    def test_most_frequent_ties_go_to_the_most_recent_event(self):
        older = [SimpleNamespace(provider="Old source", event_id=1, time=datetime(2026, 9, 20, 8, i, tzinfo=timezone.utc))
                 for i in range(2)]
        newer = [SimpleNamespace(provider="New source", event_id=2, time=datetime(2026, 9, 22, 8, i, tzinfo=timezone.utc))
                 for i in range(2)]
        groups = top_event_groups(older + newer)
        self.assertEqual([key for key, _count in groups], [("New source", 2), ("Old source", 1)])

    def test_timestamp_format(self):
        moment = datetime(2026, 9, 24, 9, 5, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        self.assertEqual(format_timestamp(moment), "2026-09-24 09:05 (UTC+05:30)")
        self.assertEqual(format_timestamp(datetime(2026, 1, 2, 3, 4)), "2026-01-02 03:04")


if __name__ == "__main__":
    unittest.main()
