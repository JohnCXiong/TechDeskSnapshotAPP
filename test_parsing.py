"""Tests for turning PowerShell JSON into results. No PowerShell is run here.

The sample data below has the same shape the real scripts print.
"""

import unittest
from datetime import datetime, timedelta, timezone

from techdesk_snapshot.checks import (
    EVENT_DISCLAIMER,
    FAILED,
    GIB,
    OK,
    REVIEW,
    as_list,
    parse_events,
    parse_network,
    parse_pc_health,
)
from techdesk_snapshot.powershell import PERMISSION_MESSAGE, DiagnosticError

PACIFIC = timezone(timedelta(hours=-7))
CHECKED_AT = datetime(2026, 9, 24, 14, 32, tzinfo=PACIFIC)


def pc_sample(**overrides):
    data = {
        "os_caption": "Microsoft Windows 11 Pro",
        "os_version": "10.0.26100",
        "os_build": "26100",
        "os_display_version": "24H2",
        "os_update_revision": 4652,
        "os_architecture": "64-bit",
        "ram_installed_bytes": 16 * GIB,
        "ram_visible_bytes": 16 * GIB - 200 * 1024**2,
        "system_drive": "C:",
        "drive_free_bytes": 120 * GIB,
        "drive_size_bytes": 476 * GIB,
        "errors": [],
    }
    data.update(overrides)
    return data


def network_sample(**overrides):
    data = {
        "adapters_up": 1,
        "physical_up": 1,
        "gateway_found": True,
        "interface_aliases": ["Wi-Fi"],
        "gateway_ping": True,
        "gateway_error": None,
        "dns_ok": True,
        "dns_address_count": 2,
        "dns_ms": 31,
        "dns_error": None,
        "dns_error_code": None,
        "tcp_ok": True,
        "tcp_ms": 48,
        "tcp_error": None,
    }
    data.update(overrides)
    return data


def event(time, log="System", provider="Service Control Manager", event_id=7000, **extra):
    return {"time": time, "log": log, "provider": provider, "event_id": event_id, **extra}


class PcHealthParsingTests(unittest.TestCase):
    def test_healthy_windows_11_pc(self):
        result = parse_pc_health(pc_sample(), CHECKED_AT)
        self.assertEqual(result.status, OK)
        rows = dict(result.rows)
        self.assertEqual(rows["Windows"], "Microsoft Windows 11 Pro, version 24H2 (build 26100.4652), 64-bit")
        self.assertEqual(rows["Installed RAM"], "16 GB")
        self.assertEqual(rows["System drive (C:) free space"], "120.0 GB free of 476.0 GB (25% free)")
        self.assertEqual(result.data.windows_build, 26100)
        self.assertFalse(result.data.is_windows_10)
        self.assertEqual(result.checked_at, CHECKED_AT)

    def test_low_disk_space_needs_review(self):
        result = parse_pc_health(pc_sample(drive_free_bytes=8 * GIB, drive_size_bytes=256 * GIB), CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        self.assertTrue(result.data.low_disk)
        self.assertIn("low disk space", result.summary)

    def test_low_percentage_on_a_big_drive_is_also_low(self):
        # 50 GB free sounds like a lot, but it is under 10% of a 1 TB drive.
        result = parse_pc_health(pc_sample(drive_free_bytes=50 * GIB, drive_size_bytes=1000 * GIB), CHECKED_AT)
        self.assertTrue(result.data.low_disk)

    def test_under_10_gb_is_low_even_when_the_percentage_looks_fine(self):
        # 9 GB of a 64 GB drive is 14% free, but only 9 GB.
        result = parse_pc_health(pc_sample(drive_free_bytes=9 * GIB, drive_size_bytes=64 * GIB), CHECKED_AT)
        self.assertTrue(result.data.low_disk)

    def test_disk_thresholds_are_exact(self):
        healthy = parse_pc_health(pc_sample(drive_free_bytes=12 * GIB, drive_size_bytes=100 * GIB), CHECKED_AT)
        self.assertFalse(healthy.data.low_disk)
        self.assertEqual(healthy.status, OK)
        boundary = parse_pc_health(pc_sample(drive_free_bytes=10 * GIB, drive_size_bytes=100 * GIB), CHECKED_AT)
        self.assertFalse(boundary.data.low_disk, "exactly 10 GB and exactly 10% is not below either limit")
        just_under = parse_pc_health(pc_sample(drive_free_bytes=10 * GIB - 1, drive_size_bytes=100 * GIB), CHECKED_AT)
        self.assertTrue(just_under.data.low_disk)

    def test_windows_10_is_flagged_but_ltsc_is_not(self):
        win10 = parse_pc_health(pc_sample(os_caption="Microsoft Windows 10 Pro", os_build="19045"), CHECKED_AT)
        self.assertTrue(win10.data.is_windows_10)
        self.assertEqual(win10.status, REVIEW)
        self.assertTrue(any("end of support" in note for note in win10.notes))

        ltsc = parse_pc_health(
            pc_sample(os_caption="Microsoft Windows 10 Enterprise LTSC", os_build="19044"), CHECKED_AT
        )
        self.assertFalse(ltsc.data.is_windows_10)
        self.assertEqual(ltsc.status, OK)

    def test_ram_falls_back_to_usable_memory_when_modules_are_not_listed(self):
        # Virtual machines often report no memory modules.
        result = parse_pc_health(pc_sample(ram_installed_bytes=None, ram_visible_bytes=int(7.8 * GIB)), CHECKED_AT)
        rows = dict(result.rows)
        self.assertEqual(rows["Usable RAM"], "7.8 GB")
        self.assertFalse(result.data.ram_is_installed)
        self.assertTrue(any("virtual machines" in note for note in result.notes))
        self.assertTrue(any("less than 8 GB" in note for note in result.notes))

    def test_permission_problem_on_one_part_keeps_the_other_parts(self):
        raw = pc_sample(
            ram_installed_bytes=None,
            ram_visible_bytes=None,
            errors=[{"part": "ram", "kind": "access_denied", "message": "Access denied"}],
        )
        result = parse_pc_health(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        self.assertEqual(dict(result.rows)["Installed RAM"], "Not available")
        self.assertIn("RAM", result.data.unavailable)
        self.assertTrue(any(PERMISSION_MESSAGE in note for note in result.notes))
        self.assertIn("Microsoft Windows 11 Pro", dict(result.rows)["Windows"])

    def test_nothing_readable_is_could_not_check(self):
        raw = {"errors": [{"part": "windows", "kind": "other", "message": "WMI is broken"}]}
        result = parse_pc_health(raw, CHECKED_AT)
        self.assertEqual(result.status, FAILED)

    def test_wrong_value_types_are_treated_as_missing(self):
        raw = pc_sample(ram_installed_bytes="lots", ram_visible_bytes=True, drive_free_bytes="n/a")
        result = parse_pc_health(raw, CHECKED_AT)
        rows = dict(result.rows)
        self.assertEqual(rows["Installed RAM"], "Not available")
        self.assertEqual(rows["System drive (C:) free space"], "Not available")

    def test_output_that_is_not_an_object_is_rejected(self):
        with self.assertRaises(DiagnosticError):
            parse_pc_health(["not", "a", "dict"], CHECKED_AT)


class NetworkParsingTests(unittest.TestCase):
    def test_everything_working(self):
        result = parse_network(network_sample(), CHECKED_AT)
        self.assertEqual(result.status, OK)
        rows = dict(result.rows)
        self.assertEqual(rows["Active connection with a default gateway"], "Yes (via Wi-Fi)")
        self.assertEqual(rows["DNS lookup of example.com"], "OK (31 ms)")
        self.assertEqual(rows["TCP connection to example.com:443"], "OK (48 ms)")
        self.assertEqual(rows["Gateway ping (for information only)"], "Replied")

    def test_failed_gateway_ping_alone_is_not_reported_as_an_outage(self):
        replied = parse_network(network_sample(gateway_ping=True), CHECKED_AT)
        no_reply = parse_network(network_sample(gateway_ping=False), CHECKED_AT)
        self.assertEqual(no_reply.status, OK, "A ping failure alone must not change the status")
        self.assertEqual(no_reply.summary, replied.summary, "A ping failure alone must not change the summary")
        self.assertEqual(dict(no_reply.rows)["Gateway ping (for information only)"], "No reply (not proof of an outage)")
        self.assertTrue(any("does not prove an outage" in note for note in no_reply.notes))

    def test_no_connected_adapter(self):
        raw = network_sample(
            adapters_up=0, physical_up=0, gateway_found=False, interface_aliases=[], gateway_ping=None,
            dns_ok=False, dns_error="DNS server failure", dns_error_code=9002, tcp_ok=None,
        )
        result = parse_network(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        self.assertIn("appears to be offline", result.summary)

    def test_only_virtual_adapters_up_still_counts_as_offline(self):
        # VMware / Hyper-V / WSL adapters stay "Up" when Wi-Fi is off or the cable is out.
        raw = network_sample(
            adapters_up=2, physical_up=0, gateway_found=False, interface_aliases=[], gateway_ping=None,
            dns_ok=False, dns_error_code=9002, tcp_ok=None,
        )
        result = parse_network(raw, CHECKED_AT)
        self.assertIn("appears to be offline", result.summary)
        self.assertTrue(any("Virtual adapters" in note for note in result.notes))

    def test_older_output_without_physical_count_uses_the_total(self):
        raw = network_sample(adapters_up=0, gateway_found=False, gateway_ping=None, dns_ok=False, tcp_ok=None)
        del raw["physical_up"]
        self.assertEqual(parse_network(raw, CHECKED_AT).data.physical_up, 0)

    def test_tcp_row_shows_which_ip_version_was_tested(self):
        ok = parse_network(network_sample(tcp_family="IPv4"), CHECKED_AT)
        self.assertEqual(dict(ok.rows)["TCP connection to example.com:443"], "OK (48 ms, IPv4)")
        failed = parse_network(
            network_sample(tcp_ok=False, tcp_ms=None, tcp_error="NetworkUnreachable", tcp_family="IPv6"), CHECKED_AT
        )
        self.assertEqual(
            dict(failed.rows)["TCP connection to example.com:443"], "Failed over IPv6: the network is unreachable"
        )
        odd = parse_network(network_sample(tcp_family="IPX"), CHECKED_AT)
        self.assertIsNone(odd.data.tcp_family)

    def test_adapter_up_but_no_default_gateway(self):
        raw = network_sample(gateway_found=False, interface_aliases=[], gateway_ping=None, dns_ok=False, tcp_ok=None)
        result = parse_network(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        self.assertIn("default gateway", result.summary)
        self.assertEqual(dict(result.rows)["Active connection with a default gateway"], "No")

    def test_dns_failure_uses_friendly_text_and_skips_tcp(self):
        raw = network_sample(dns_ok=False, dns_error="example.com : DNS name does not exist", dns_error_code=9003, tcp_ok=None)
        result = parse_network(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        self.assertIn("DNS problem", result.summary)
        self.assertEqual(result.data.dns_problem, "the DNS server says the name does not exist")
        self.assertIsNone(result.data.tcp_ok)
        self.assertEqual(dict(result.rows)["TCP connection to example.com:443"], "Not tested (DNS lookup failed)")

    def test_unknown_dns_error_text_stays_out_of_the_structured_data(self):
        raw = network_sample(dns_ok=False, dns_error="Server 10.0.0.53 said no", dns_error_code=12345, tcp_ok=None)
        result = parse_network(raw, CHECKED_AT)
        self.assertEqual(result.data.dns_problem, "the lookup failed")
        # Shown in the window for the technician, but not stored where the note reads from.
        self.assertTrue(any("10.0.0.53" in note for note in result.notes))

    def test_tcp_refused_after_dns_worked(self):
        raw = network_sample(tcp_ok=False, tcp_ms=None, tcp_error="ConnectionRefused")
        result = parse_network(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        self.assertIn("HTTPS", result.summary)
        self.assertEqual(result.data.tcp_problem, "the connection was refused")

    def test_tcp_result_is_ignored_if_dns_failed(self):
        raw = network_sample(dns_ok=False, tcp_ok=True)
        result = parse_network(raw, CHECKED_AT)
        self.assertIsNone(result.data.tcp_ok)

    def test_single_interface_alias_sent_as_plain_string(self):
        # Windows PowerShell 5.1 can turn a one-item list into a plain value.
        result = parse_network(network_sample(interface_aliases="Ethernet"), CHECKED_AT)
        self.assertEqual(result.data.interface_aliases, ("Ethernet",))

    def test_adapter_query_error(self):
        raw = network_sample(
            adapters_up=0, physical_up=0, gateway_found=False, interface_aliases=[], gateway_ping=None,
            gateway_error="Access denied", dns_ok=True, tcp_ok=True,
        )
        result = parse_network(raw, CHECKED_AT)
        self.assertEqual(result.status, OK)  # DNS and HTTPS worked, so the internet is reachable
        self.assertEqual(dict(result.rows)["Active connection with a default gateway"], "Could not check")
        self.assertFalse(any("VPN or proxy" in note for note in result.notes), "the gateway was not checked, not missing")

    def test_adapter_query_error_is_not_reported_as_offline(self):
        raw = network_sample(
            adapters_up=0, physical_up=0, gateway_found=False, interface_aliases=[], gateway_ping=None,
            gateway_error="Access denied", dns_ok=False, dns_error_code=9002, tcp_ok=None,
        )
        result = parse_network(raw, CHECKED_AT)
        self.assertIn("adapter information could not be read", result.summary)
        self.assertNotIn("offline", result.summary)


class EventParsingTests(unittest.TestCase):
    def test_events_are_sorted_newest_first(self):
        raw = {"days": 7, "per_log_limit": 20, "events": [
            event("2026-09-20T08:00:00-07:00", log="Application", provider="Application Error", event_id=1000),
            event("2026-09-23T09:15:00-07:00"),
        ], "log_errors": []}
        result = parse_events(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        times = [e.time for e in result.data.events]
        self.assertEqual(times, sorted(times, reverse=True))
        self.assertEqual(result.data.events[0].provider, "Service Control Manager")
        self.assertEqual(result.data.events[0].time.utcoffset(), timedelta(hours=-7))
        self.assertIn("2 Error events", result.summary)
        self.assertIn(EVENT_DISCLAIMER, result.notes)

    def test_at_most_20_events_across_both_logs(self):
        start = datetime(2026, 9, 23, 12, 0, tzinfo=PACIFIC)
        items = [event((start - timedelta(minutes=i)).isoformat(), log="System") for i in range(15)]
        items += [event((start - timedelta(minutes=i, seconds=30)).isoformat(), log="Application") for i in range(15)]
        result = parse_events({"days": 7, "per_log_limit": 20, "events": items, "log_errors": []}, CHECKED_AT)
        self.assertEqual(len(result.data.events), 20)
        self.assertTrue(result.data.possibly_more)
        self.assertIn("There may be more", result.summary)
        # The 20 kept must be the 20 newest.
        newest = sorted((datetime.fromisoformat(i["time"]) for i in items), reverse=True)[:20]
        self.assertEqual([e.time for e in result.data.events], newest)

    def test_hitting_the_per_log_limit_means_there_may_be_more(self):
        items = [event(f"2026-09-23T10:{i:02d}:00-07:00") for i in range(20)]
        result = parse_events({"days": 7, "per_log_limit": 20, "events": items, "log_errors": []}, CHECKED_AT)
        self.assertTrue(result.data.possibly_more)

    def test_exactly_20_events_below_both_limits_is_complete(self):
        items = [event(f"2026-09-23T10:{i:02d}:00-07:00") for i in range(10)]
        items += [event(f"2026-09-23T11:{i:02d}:00-07:00", log="Application") for i in range(10)]
        result = parse_events({"days": 7, "per_log_limit": 20, "events": items, "log_errors": []}, CHECKED_AT)
        self.assertEqual(len(result.data.events), 20)
        self.assertFalse(result.data.possibly_more)
        self.assertIn("20 Error events in the last 7 days", result.summary)

    def test_no_matching_events(self):
        result = parse_events({"days": 7, "per_log_limit": 20, "events": [], "log_errors": []}, CHECKED_AT)
        self.assertEqual(result.status, OK)
        self.assertEqual(result.data.events, ())
        self.assertIn("No Error events", result.summary)

    def test_single_event_sent_as_object_instead_of_list(self):
        raw = {"days": 7, "events": event("2026-09-23T09:15:00-07:00"), "log_errors": None}
        result = parse_events(raw, CHECKED_AT)
        self.assertEqual(len(result.data.events), 1)

    def test_powershell_value_count_wrapper_is_unwrapped(self):
        raw = {"days": 7, "events": {"value": [event("2026-09-23T09:15:00-07:00")], "Count": 1}}
        result = parse_events(raw, CHECKED_AT)
        self.assertEqual(len(result.data.events), 1)

    def test_bad_entries_are_skipped_not_fatal(self):
        raw = {"days": 7, "events": [
            event("not a time"),
            event("2026-09-23T09:15:00-07:00", event_id="7000"),
            event("2026-09-23T09:15:00-07:00", event_id=True),
            "garbage",
            event("2026-09-23T09:16:00-07:00", provider=None),
        ]}
        result = parse_events(raw, CHECKED_AT)
        self.assertEqual(len(result.data.events), 1)
        self.assertEqual(result.data.events[0].provider, "Unknown source")

    def test_event_message_text_is_never_kept(self):
        raw = {"days": 7, "events": [event("2026-09-23T09:15:00-07:00", message="Secret message for jdoe")]}
        result = parse_events(raw, CHECKED_AT)
        self.assertFalse(hasattr(result.data.events[0], "message"))
        self.assertNotIn("Secret message", repr(result))

    def test_one_log_denied(self):
        raw = {"days": 7, "events": [event("2026-09-23T09:15:00-07:00")], "log_errors": [
            {"log": "Application", "kind": "access_denied", "message": "Attempted to perform an unauthorized operation."},
        ]}
        result = parse_events(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW)
        self.assertEqual(result.data.unreadable_logs, ("Application",))
        self.assertTrue(any("standard permissions" in note for note in result.notes))

    def test_one_log_denied_and_no_events_is_not_ok(self):
        raw = {"days": 7, "events": [], "log_errors": [
            {"log": "Application", "kind": "access_denied", "message": "Attempted to perform an unauthorized operation."},
        ]}
        result = parse_events(raw, CHECKED_AT)
        self.assertEqual(result.status, REVIEW, "half the data is missing, so the badge must not be green")
        self.assertIn("logs that could be read", result.summary)
        self.assertTrue(any("standard permissions" in note for note in result.notes))

    def test_both_logs_unreadable_is_could_not_check(self):
        raw = {"days": 7, "events": [], "log_errors": [
            {"log": "System", "kind": "access_denied", "message": "denied"},
            {"log": "Application", "kind": "other", "message": "The RPC server is unavailable"},
        ]}
        result = parse_events(raw, CHECKED_AT)
        self.assertEqual(result.status, FAILED)

    def test_time_without_offset_is_treated_as_local(self):
        result = parse_events({"days": 7, "events": [event("2026-09-23T09:15:00")]}, CHECKED_AT)
        self.assertIsNotNone(result.data.events[0].time.tzinfo)


class AsListTests(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(as_list(None), [])
        self.assertEqual(as_list([1, 2]), [1, 2])
        self.assertEqual(as_list({"a": 1}), [{"a": 1}])
        self.assertEqual(as_list("x"), ["x"])
        self.assertEqual(as_list({"value": [1], "Count": 1}), [1])


if __name__ == "__main__":
    unittest.main()
