"""Build the ticket note that the Copy Ticket Note button copies.

Two layers keep private details out of the note:

1. Allowlist. The note is built only from specific fields that are known to
   be safe: statuses, Windows version, RAM, disk space, pass/fail results,
   and each event's time, log, source and ID. Raw error text, adapter names
   and the notes shown in the window are never copied in.
2. Safety net, as a backup.
   * Each value that came from Windows (the Windows version text, drive
     letter, event source and log names) is checked for this PC's computer
     name, username and domain.
   * The whole finished note is then scanned for common forms of IP
     addresses (IPv4 and IPv6), MAC addresses, email addresses, and user
     folder or network paths.
   Anything found is replaced with [redacted].

The note's own fixed sentences are never checked against the username.
Otherwise a PC whose account is literally named "User" would turn "with the
user" into "with the [redacted]".
"""

from __future__ import annotations

import getpass
import ipaddress
import ntpath
import os
import re
import socket
from collections import Counter
from datetime import datetime
from typing import Callable, Iterable

from . import APP_NAME
from .checks import (
    DNS_TEST_NAME,
    TCP_TEST_PORT,
    CheckResult,
    EventsData,
    NetworkData,
    PcHealthData,
    format_disk,
    format_ram,
    is_offline,
)

REDACTED = "[redacted]"
MAX_NEXT_CHECKS = 6
TOP_EVENT_GROUPS = 3
REPEATED_EVENT_THRESHOLD = 3

# Account and computer names that are ordinary words. They do not identify
# anyone, and removing them would damage real event sources such as
# "Microsoft-Windows-User Profiles Service" or "Service Control Manager".
GENERIC_NAMES = frozenset({
    "admin", "administrator", "computer", "default", "desktop", "guest", "home",
    "laptop", "localhost", "office", "owner", "server", "service", "system",
    "test", "user", "users", "windows", "workgroup",
})

Clean = Callable[[str], str]


def build_ticket_note(
    pc: CheckResult | None = None,
    network: CheckResult | None = None,
    events: CheckResult | None = None,
    *,
    identifiers: Iterable[str] | None = None,
) -> str:
    """Return the note text. Checks that have not been run are listed as "Not run".

    ``identifiers`` are the names to remove (the tests pass fake ones). By
    default the real computer name, username and domain of this PC are used.
    """
    names = list(local_identifiers() if identifiers is None else identifiers)

    def clean(value: str) -> str:
        """Safety net for one value that came from Windows."""
        return redact(value, names)

    finished = [r for r in (pc, network, events) if r is not None]
    lines = [f"{APP_NAME} - ticket note"]
    if finished:
        first = min(r.checked_at for r in finished)
        last = max(r.checked_at for r in finished)
        when = format_timestamp(first)
        if last.strftime("%Y-%m-%d %H:%M") != first.strftime("%Y-%m-%d %H:%M"):
            when += f" to {format_timestamp(last)}"
        lines.append(f"Checks run: {when}")
    else:
        lines.append("Checks run: none yet")

    lines += [""] + _pc_section(pc, clean)
    lines += [""] + _network_section(network)
    lines += [""] + _events_section(events, clean)
    lines += ["", "SUGGESTED NEXT CHECKS"]
    lines += [f"- {item}" for item in suggest_next_checks(pc, network, events, clean)]
    lines += [
        "",
        "Read-only snapshot: nothing was changed on the PC. Computer name, username, "
        "IP addresses and event message text are intentionally left out.",
    ]
    # Last step: scan the whole note for anything that looks like an address or path.
    return redact("\n".join(lines))


# ---------------------------------------------------------------------------
# Sections (built only from allowlisted fields)
# ---------------------------------------------------------------------------


def _heading(title: str, result: CheckResult | None) -> str:
    if result is None:
        return f"{title.upper()} - Not run"
    return f"{title.upper()} - {result.status} (checked {result.checked_at.strftime('%H:%M')})"


def _not_finished(result: CheckResult | None) -> list[str]:
    if result is None:
        return ["- This check was not run."]
    return ["- The check could not finish. Re-run it or collect this information manually."]


def _pc_section(result: CheckResult | None, clean: Clean) -> list[str]:
    lines = [_heading("PC Health", result)]
    data = result.data if result else None
    if not isinstance(data, PcHealthData):
        return lines + _not_finished(result)
    ram_label = "Installed RAM" if data.ram_is_installed or data.ram_gb is None else "Usable RAM"
    drive = f"System drive ({clean(data.system_drive)})" if data.system_drive else "System drive"
    lines += [
        f"- Windows: {clean(data.windows) if data.windows else 'Not available'}",
        f"- {ram_label}: {format_ram(data.ram_gb)}",
        f"- {drive}: {format_disk(data)}",
    ]
    if data.low_disk:
        lines.append("- Finding: free disk space is low.")
    if data.is_windows_10:
        lines.append("- Finding: Windows 10 reached end of support on 14 October 2025.")
    return lines


def _network_section(result: CheckResult | None) -> list[str]:
    # Every value here is one of the app's own fixed phrases, so nothing
    # from Windows needs cleaning.
    lines = [_heading("Network Check", result)]
    data = result.data if result else None
    if not isinstance(data, NetworkData):
        return lines + _not_finished(result)

    if data.gateway_found:
        gateway = "Yes"
    elif data.gateway_problem:
        gateway = "Could not check"
    else:
        gateway = "No"

    if data.dns_ok:
        dns = "OK"
    else:
        dns = f"Failed ({data.dns_problem})" if data.dns_problem else "Failed"

    over = f" over {data.tcp_family}" if data.tcp_family else ""
    if data.tcp_ok is None:
        tcp = "Not tested (no DNS answer)"
    elif data.tcp_ok:
        tcp = f"OK{over}"
    else:
        tcp = f"Failed{over} ({data.tcp_problem})" if data.tcp_problem else f"Failed{over}"

    if data.gateway_ping is True:
        ping = "Replied"
    elif data.gateway_ping is False:
        ping = "No reply (for information only: many routers ignore ping, so this is not proof of an outage)"
    else:
        ping = "Not tested"

    lines += [
        f"- Active connection with a default gateway: {gateway}",
        f"- DNS lookup of {DNS_TEST_NAME}: {dns}",
        f"- HTTPS connection (TCP {TCP_TEST_PORT}) to {DNS_TEST_NAME}: {tcp}",
        f"- Gateway ping: {ping}",
        f"- Result: {result.summary}",
    ]
    return lines


def _events_section(result: CheckResult | None, clean: Clean) -> list[str]:
    lines = [_heading("Recent Errors", result)]
    data = result.data if result else None
    if not isinstance(data, EventsData):
        return lines + _not_finished(result)

    events = data.events
    if events:
        by_log = Counter(clean(e.log) for e in events)
        breakdown = ", ".join(f"{log}: {count}" for log, count in sorted(by_log.items()))
        if data.possibly_more:
            # Only the newest ones were fetched, so these numbers are not a full 7-day count.
            lines.append(
                f"- The {len(events)} most recent Error events from the last {data.days} days "
                f"(more may exist). Among these: {breakdown}"
            )
        else:
            lines.append(
                f"- {len(events)} Error event{'s' if len(events) != 1 else ''} "
                f"in the last {data.days} days ({breakdown})"
            )
        latest = events[0]
        lines.append(
            f"- Most recent: {latest.time.strftime('%Y-%m-%d %H:%M')}, {clean(latest.log)}, "
            f"{clean(latest.provider)}, Event ID {latest.event_id}"
        )
        lines.append("- Most frequent (source, Event ID, count):")
        for (provider, event_id), count in top_event_groups(events):
            lines.append(f"    {clean(provider)}, Event ID {event_id}: {count}")
        lines.append("- An event on its own does not prove what caused a problem.")
    elif data.nothing_read:
        lines.append("- No log could be read, so recent errors are unknown.")
    elif data.unreadable_logs:
        lines.append(f"- No Error events found in the logs that could be read (last {data.days} days).")
    else:
        lines.append(f"- No Error events found in the last {data.days} days.")
    if data.unreadable_logs:
        logs = ", ".join(clean(log) for log in data.unreadable_logs)
        lines.append(f"- Could not read: {logs} log")
    return lines


def top_event_groups(events: Iterable, limit: int = TOP_EVENT_GROUPS) -> list[tuple[tuple[str, int], int]]:
    """The most common (source, Event ID) pairs. Ties go to the most recent event."""
    events = list(events)
    counts = Counter((e.provider, e.event_id) for e in events)
    latest: dict[tuple[str, int], datetime] = {}
    for e in events:
        key = (e.provider, e.event_id)
        if key not in latest or e.time > latest[key]:
            latest[key] = e.time
    ordered = sorted(counts.items(), key=lambda item: (-item[1], -latest[item[0]].timestamp()))
    return ordered[:limit]


# ---------------------------------------------------------------------------
# Suggested next checks
# ---------------------------------------------------------------------------


def suggest_next_checks(
    pc: CheckResult | None,
    network: CheckResult | None,
    events: CheckResult | None,
    clean: Clean = lambda value: value,
) -> list[str]:
    """Sensible, safe next steps based on the results. Nothing here changes the PC."""
    items = ["Confirm the exact symptom, when it started, and whether other users or devices are affected."]

    pc_data = pc.data if pc else None
    if pc is not None and (not isinstance(pc_data, PcHealthData) or pc_data.unavailable):
        items.append("Re-run PC Health, or check Settings > System > About and Storage manually.")
    if isinstance(pc_data, PcHealthData):
        if pc_data.low_disk:
            items.append(
                "Free space is low. Review Settings > System > Storage with the user before removing anything."
            )
        if pc_data.is_windows_10:
            items.append("Confirm whether this PC has Windows 10 Extended Security Updates or a Windows 11 upgrade plan.")

    net = network.data if network else None
    if network is not None and not isinstance(net, NetworkData):
        items.append(f"Re-run Network Check, or test with: Test-NetConnection {DNS_TEST_NAME} -Port {TCP_TEST_PORT}")
    elif isinstance(net, NetworkData) and not (net.dns_ok and net.tcp_ok):
        if is_offline(net):
            items.append("Check Wi-Fi, airplane mode, the network cable, and that the network adapter is enabled.")
        elif not net.gateway_found:
            items.append("Run ipconfig /all to see whether the adapter received an address and default gateway (DHCP).")
        elif not net.dns_ok:
            items.append(
                f"Run nslookup {DNS_TEST_NAME}, check the DNS servers in ipconfig /all, and compare with another device."
            )
        else:
            items.append("Check whether websites open in a browser, then review proxy, VPN and firewall settings.")

    ev = events.data if events else None
    if events is not None and not isinstance(ev, EventsData):
        items.append("Re-run Recent Errors, or review Windows Logs > System and Application in Event Viewer.")
    elif isinstance(ev, EventsData):
        if ev.events:
            (provider, event_id), count = top_event_groups(ev.events, limit=1)[0]
            if count >= REPEATED_EVENT_THRESHOLD:
                where = f" among the {len(ev.events)} most recent errors" if ev.possibly_more else ""
                items.append(
                    f"{clean(provider)} Event ID {event_id} appears {count} times{where}. Look it up and "
                    "check whether its times match the reported problem."
                )
            items.append("In Event Viewer, compare the listed event times with when the user saw the problem.")
        if ev.access_denied_logs:
            items.append("Some logs could not be read with standard permissions. Ask an administrator if they are needed.")
        elif ev.unreadable_logs:
            items.append("Re-run Recent Errors, or review Windows Logs > System and Application in Event Viewer.")

    return items[:MAX_NEXT_CHECKS]


# ---------------------------------------------------------------------------
# Redaction safety net
# ---------------------------------------------------------------------------

_MAC = re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*")
_USER_FOLDER = re.compile(r"(?i)\b([a-z]:[\\/]users[\\/])[^\\/\r\n]+")
_UNC_PATH = re.compile(r"(?<!\\)\\\\[^\\\s]+")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")
_IPV6_CANDIDATE = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]*(?:%[\w.]+)?(?![\w:])")


def redact(text: str, identifiers: Iterable[str] = ()) -> str:
    """Replace anything that looks private with [redacted].

    ``identifiers`` are names (computer name, username, domain) to remove as
    whole words, ignoring case. Names shorter than 3 letters, and generic
    names such as "User", are skipped because they would remove ordinary words.
    """
    text = _USER_FOLDER.sub(lambda m: m.group(1) + REDACTED, text)
    text = _UNC_PATH.sub(lambda m: "\\\\" + REDACTED, text)
    text = _EMAIL.sub(REDACTED, text)
    text = _MAC.sub(REDACTED, text)
    # IPv6 first, so an address such as ::ffff:192.0.2.1 is removed whole.
    text = _IPV6_CANDIDATE.sub(_redact_ipv6, text)
    text = _IPV4.sub(_redact_ipv4, text)

    names = {v.strip() for v in identifiers if v and len(v.strip()) >= 3}
    names = {v for v in names if v.lower() not in GENERIC_NAMES}
    # Longest first, so "DESKTOP-ABC123" is removed before a shorter value inside it.
    for value in sorted(names, key=len, reverse=True):
        # [^\W_] means "a letter or digit", so "Backup_jdoe" still matches "jdoe".
        pattern = r"(?<![^\W_])" + re.escape(value) + r"(?![^\W_])"
        text = re.sub(pattern, REDACTED, text, flags=re.IGNORECASE)
    return text


def _redact_ipv4(match: re.Match) -> str:
    text = match.group(0)
    parts = [int(part) for part in text.split(".")]
    if any(part > 255 for part in parts):
        return text  # a version number such as 10.0.300.1
    if parts[1:] == [0, 0, 0]:
        return text  # a version such as "SMSvcHost 4.0.0.0", never a device's address
    return REDACTED


def _redact_ipv6(match: re.Match) -> str:
    candidate = match.group(0)
    trailing = ""
    while candidate.endswith("."):  # a full stop at the end of a sentence
        candidate, trailing = candidate[:-1], trailing + "."
    try:
        ipaddress.IPv6Address(candidate.split("%", 1)[0])
    except ValueError:
        return match.group(0)  # e.g. a time such as 14:32:05
    return REDACTED + trailing


def local_identifiers() -> list[str]:
    """This PC's computer name, username and domain, used by the safety net.

    They are read in memory only, to remove them from the note. They are
    never shown, copied or saved.
    """
    values = {
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("USERNAME", ""),
        os.environ.get("USERDOMAIN", ""),
        os.environ.get("USERDNSDOMAIN", ""),
        os.environ.get("LOGONSERVER", "").lstrip("\\"),
        ntpath.basename(os.environ.get("USERPROFILE", "").rstrip("\\/")),
    }
    try:
        hostname = socket.gethostname()
        values.update({hostname, hostname.split(".")[0]})
    except OSError:
        pass
    try:
        values.add(getpass.getuser())
    except Exception:  # getuser raises different errors on different systems
        pass
    return sorted(v for v in values if v and len(v) >= 3)


def format_timestamp(moment: datetime) -> str:
    """e.g. '2026-09-24 14:32 (UTC-07:00)'."""
    text = moment.strftime("%Y-%m-%d %H:%M")
    offset = moment.strftime("%z")
    if offset:
        text += f" (UTC{offset[:3]}:{offset[3:5]})"
    return text
