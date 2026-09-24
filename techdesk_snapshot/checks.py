"""The three diagnostic checks: PC Health, Network Check and Recent Errors.

Each check has three parts:

1. A fixed, read-only PowerShell script that prints one line of JSON.
2. A parse_* function that turns that JSON into a CheckResult. These
   functions are plain Python, so the tests can feed them sample data
   without running PowerShell.
3. A run_* function that joins 1 and 2 and turns any failure into a
   friendly "Could not check" result. The window never crashes because
   a check failed.

Privacy: each script outputs only the fields the app shows. The computer
name, the username and event message text never leave PowerShell, and the
gateway address is used inside PowerShell for the ping but never printed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from .powershell import PERMISSION_MESSAGE, DiagnosticError, run_powershell_json

# Status labels shown on the coloured badge in the window and in the ticket note.
OK = "OK"
REVIEW = "Review"
FAILED = "Could not check"

GIB = 1024**3  # Windows (e.g. File Explorer) shows sizes in 1024-based "GB".

LOW_DISK_PERCENT = 10.0
LOW_DISK_GB = 10.0
LOW_RAM_GB = 8.0
EVENT_DAYS = 7
MAX_EVENTS = 20
DNS_TEST_NAME = "example.com"
TCP_TEST_PORT = 443

PC_HEALTH_TIMEOUT = 30
NETWORK_TIMEOUT = 45
EVENTS_TIMEOUT = 60

EVENT_DISCLAIMER = (
    "An event on its own does not prove what caused a problem. Many Windows errors "
    "are harmless or repeat routinely, so compare event times with when the user "
    "actually noticed the issue."
)
PING_NO_REPLY_NOTE = (
    "The default gateway did not reply to ping. Many routers and firewalls ignore "
    "ping on purpose, so this on its own does not prove an outage."
)

# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """What the window shows for one check, plus typed data for the ticket note."""

    title: str
    checked_at: datetime
    status: str
    summary: str
    rows: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    data: Any = None  # PcHealthData, NetworkData or EventsData. None if the check failed.


@dataclass(frozen=True)
class PcHealthData:
    windows: str | None
    windows_build: int | None
    is_windows_10: bool
    ram_gb: float | None
    ram_is_installed: bool  # True: total of the memory modules. False: memory Windows can use.
    system_drive: str | None
    free_gb: float | None
    total_gb: float | None
    unavailable: tuple[str, ...] = ()

    @property
    def free_percent(self) -> float | None:
        if self.free_gb is None or not self.total_gb:
            return None
        return self.free_gb / self.total_gb * 100

    @property
    def low_disk(self) -> bool:
        percent = self.free_percent
        if percent is None or self.free_gb is None:
            return False
        return percent < LOW_DISK_PERCENT or self.free_gb < LOW_DISK_GB


@dataclass(frozen=True)
class NetworkData:
    adapters_up: int  # all adapters that are Up, including virtual ones
    physical_up: int  # physical adapters (Wi-Fi, Ethernet) that are Up
    gateway_found: bool
    gateway_ping: bool | None  # None means ping was not attempted
    dns_ok: bool
    tcp_ok: bool | None  # None means the TCP test was skipped (no DNS answer)
    interface_aliases: tuple[str, ...] = ()
    dns_problem: str | None = None
    tcp_problem: str | None = None
    dns_ms: int | None = None
    tcp_ms: int | None = None
    gateway_problem: str | None = None
    tcp_family: str | None = None  # "IPv4" or "IPv6"


@dataclass(frozen=True)
class EventRecord:
    time: datetime
    log: str
    provider: str
    event_id: int


@dataclass(frozen=True)
class EventsData:
    events: tuple[EventRecord, ...]
    days: int
    possibly_more: bool
    unreadable_logs: tuple[str, ...] = ()  # logs that could not be read, for any reason
    access_denied_logs: tuple[str, ...] = ()  # the ones that failed because of permissions

    @property
    def nothing_read(self) -> bool:
        """Neither log could be read, so the error count is unknown."""
        return len(self.unreadable_logs) >= 2 and not self.events


# ---------------------------------------------------------------------------
# PC Health
# ---------------------------------------------------------------------------

PC_HEALTH_SCRIPT = r"""
$result = [ordered]@{
    os_caption         = $null
    os_version         = $null
    os_build           = $null
    os_display_version = $null
    os_update_revision = $null
    os_architecture    = $null
    ram_installed_bytes = $null
    ram_visible_bytes   = $null
    system_drive        = $env:SystemDrive
    drive_free_bytes    = $null
    drive_size_bytes    = $null
    errors              = @()
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption, Version, BuildNumber, OSArchitecture -ErrorAction Stop
    $result.os_caption      = $os.Caption
    $result.os_version      = $os.Version
    $result.os_build        = $os.BuildNumber
    $result.os_architecture = $os.OSArchitecture
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.os_display_version = (Get-ItemProperty -Path $key -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
    $result.os_update_revision = (Get-ItemProperty -Path $key -Name UBR -ErrorAction SilentlyContinue).UBR
} catch {
    $result.errors += [pscustomobject]@{ part = 'windows'; kind = (Get-ErrorKind $_); message = $_.Exception.Message }
}

try {
    $modules = @(Get-CimInstance -ClassName Win32_PhysicalMemory -Property Capacity -ErrorAction Stop)
    if ($modules.Count -gt 0) {
        $result.ram_installed_bytes = [int64](($modules | Measure-Object -Property Capacity -Sum).Sum)
    }
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -Property TotalPhysicalMemory -ErrorAction Stop
    $result.ram_visible_bytes = [int64]$computer.TotalPhysicalMemory
} catch {
    $result.errors += [pscustomobject]@{ part = 'ram'; kind = (Get-ErrorKind $_); message = $_.Exception.Message }
}

try {
    # Ask for the system drive only, e.g. DeviceID='C:'. (Two single quotes
    # inside a single-quoted string make one quote.) Listing every drive could
    # wait on slow or disconnected network drives.
    $diskFilter = 'DeviceID=''' + $env:SystemDrive + ''''
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter $diskFilter -Property DeviceID, FreeSpace, Size -ErrorAction Stop |
        Select-Object -First 1
    if ($disk) {
        $result.drive_free_bytes = [int64]$disk.FreeSpace
        $result.drive_size_bytes = [int64]$disk.Size
    }
} catch {
    $result.errors += [pscustomobject]@{ part = 'disk'; kind = (Get-ErrorKind $_); message = $_.Exception.Message }
}

ConvertTo-TechDeskJson ([pscustomobject]$result)
"""


def parse_pc_health(raw: Any, checked_at: datetime) -> CheckResult:
    """Turn the PC Health JSON into a CheckResult."""
    raw = _require_dict(raw)
    errors = _error_parts(raw)

    windows, build = _describe_windows(raw)
    caption = str(raw.get("os_caption") or "")
    is_windows_10 = "windows 10" in caption.lower() and not any(
        edition in caption.upper() for edition in ("LTSC", "LTSB")
    )

    installed = _positive_number(raw.get("ram_installed_bytes"))
    visible = _positive_number(raw.get("ram_visible_bytes"))
    if installed is not None:
        ram_gb, ram_is_installed = installed / GIB, True
    elif visible is not None:
        ram_gb, ram_is_installed = visible / GIB, False
    else:
        ram_gb, ram_is_installed = None, False

    drive = _clean_text(raw.get("system_drive")) or None
    free = _non_negative_number(raw.get("drive_free_bytes"))
    size = _positive_number(raw.get("drive_size_bytes"))
    free_gb = free / GIB if free is not None and size is not None else None
    total_gb = size / GIB if free is not None and size is not None else None

    unavailable = []
    if windows is None:
        unavailable.append("Windows version")
    if ram_gb is None:
        unavailable.append("RAM")
    if free_gb is None:
        unavailable.append("disk space")

    data = PcHealthData(
        windows=windows,
        windows_build=build,
        is_windows_10=is_windows_10,
        ram_gb=ram_gb,
        ram_is_installed=ram_is_installed,
        system_drive=drive,
        free_gb=free_gb,
        total_gb=total_gb,
        unavailable=tuple(unavailable),
    )

    drive_label = f"System drive ({drive})" if drive else "System drive"
    rows = [
        ("Windows", windows or "Not available"),
        ("Installed RAM" if ram_is_installed or ram_gb is None else "Usable RAM", format_ram(ram_gb)),
        (f"{drive_label} free space", format_disk(data)),
    ]

    notes: list[str] = []
    findings: list[str] = []
    if data.low_disk:
        findings.append("low disk space")
        notes.append(
            f"Free space is low (under {LOW_DISK_PERCENT:g}% or under {LOW_DISK_GB:g} GB). "
            "Windows updates can fail and apps can slow down or crash when the system drive is nearly full."
        )
    if is_windows_10:
        findings.append("Windows 10 is out of support")
        notes.append(
            "Windows 10 reached end of support on 14 October 2025. Check whether this PC is "
            "enrolled in Extended Security Updates (ESU) or scheduled for a Windows 11 upgrade."
        )
    if ram_gb is not None and ram_gb < LOW_RAM_GB:
        notes.append(
            f"This PC has less than {LOW_RAM_GB:g} GB of RAM. That can feel slow with many browser "
            "tabs or Teams open. This is worth knowing if the ticket is about slowness."
        )
    if not ram_is_installed and ram_gb is not None:
        notes.append(
            "Windows did not list the memory modules (this is common in virtual machines), "
            "so this is the amount of memory Windows can use rather than the amount installed."
        )
    for part, message, kind in errors:
        notes.append(_partial_failure_note(part, message, kind))

    if len(unavailable) == 3:
        status = FAILED
        summary = "None of the PC Health details could be read."
    elif findings:
        status = REVIEW
        summary = "Needs a look: " + " and ".join(findings) + "."
    elif unavailable:
        status = REVIEW
        summary = "Some details could not be read: " + ", ".join(unavailable) + "."
    else:
        status = OK
        summary = "Windows version, RAM and free disk space collected. Nothing unusual found."

    return CheckResult("PC Health", checked_at, status, summary, rows, notes, data)


def _describe_windows(raw: dict) -> tuple[str | None, int | None]:
    """Build e.g. 'Microsoft Windows 11 Pro, version 24H2 (build 26100.4652), 64-bit'."""
    caption = _clean_text(raw.get("os_caption"))
    build_text = _clean_text(raw.get("os_build"))
    build = int(build_text) if build_text.isdigit() else None
    if not caption and build is None:
        return None, None

    text = caption or "Windows"
    display_version = _clean_text(raw.get("os_display_version"))
    if display_version:
        text += f", version {display_version}"
    if build is not None:
        revision = raw.get("os_update_revision")
        if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 0:
            text += f" (build {build}.{revision})"
        else:
            text += f" (build {build})"
    architecture = _clean_text(raw.get("os_architecture"))
    if architecture:
        text += f", {architecture}"
    return text, build


def format_ram(ram_gb: float | None) -> str:
    if ram_gb is None:
        return "Not available"
    rounded = round(ram_gb, 1)
    return f"{rounded:g} GB" if rounded == int(rounded) else f"{rounded:.1f} GB"


def format_disk(data: PcHealthData) -> str:
    if data.free_gb is None or data.total_gb is None:
        return "Not available"
    return f"{data.free_gb:.1f} GB free of {data.total_gb:.1f} GB ({data.free_percent:.0f}% free)"


def run_pc_health() -> CheckResult:
    return _run_check("PC Health", PC_HEALTH_SCRIPT, PC_HEALTH_TIMEOUT, parse_pc_health)


# ---------------------------------------------------------------------------
# Network Check
# ---------------------------------------------------------------------------

NETWORK_SCRIPT = r"""
$result = [ordered]@{
    adapters_up       = 0
    physical_up       = 0
    gateway_found     = $false
    interface_aliases = @()
    gateway_ping      = $null
    gateway_error     = $null
    dns_ok            = $false
    dns_address_count = 0
    dns_ms            = $null
    dns_error         = $null
    dns_error_code    = $null
    tcp_ok            = $null
    tcp_ms            = $null
    tcp_error         = $null
    tcp_family        = $null
}
$hasIPv4Route = $false
$hasIPv6Route = $false

# 1. Is there a connected adapter with a default gateway (a way off the local network)?
try {
    $upAdapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
    $result.adapters_up = $upAdapters.Count
    # Virtual adapters (VMware, Hyper-V, WSL, Docker) stay Up even when Wi-Fi
    # is off or the cable is unplugged, so physical adapters are counted separately.
    $result.physical_up = @($upAdapters | Where-Object { -not $_.Virtual }).Count
    $upIndexes = @($upAdapters | ForEach-Object { $_.ifIndex })
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue |
        Where-Object { ($upIndexes -contains $_.ifIndex) -and ($_.NextHop -ne '0.0.0.0') -and ($_.NextHop -ne '::') } |
        Sort-Object -Property RouteMetric)
    if ($routes.Count -gt 0) {
        $result.gateway_found = $true
        $result.interface_aliases = @($routes | ForEach-Object { $_.InterfaceAlias } | Select-Object -Unique)
        $hasIPv4Route = @($routes | Where-Object { $_.AddressFamily -eq 'IPv4' }).Count -gt 0
        $hasIPv6Route = @($routes | Where-Object { $_.AddressFamily -eq 'IPv6' }).Count -gt 0

        # Optional extra: ping the IPv4 gateway twice. The address is used here
        # and never printed. No reply is NOT proof of an outage.
        $ipv4Route = $routes | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
        if ($ipv4Route) {
            $result.gateway_ping = $false
            $ping = New-Object System.Net.NetworkInformation.Ping
            foreach ($attempt in 1..2) {
                try {
                    if ($ping.Send($ipv4Route.NextHop, 1000).Status -eq 'Success') {
                        $result.gateway_ping = $true
                        break
                    }
                } catch { }
            }
            $ping.Dispose()
        }
    }
} catch {
    $result.gateway_error = $_.Exception.Message
}

# 2. Can DNS turn example.com into an address?
$address = $null
$timer = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $answers = @(Resolve-DnsName -Name 'example.com' -Type A_AAAA -DnsOnly -QuickTimeout -ErrorAction Stop |
        Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' })
    $result.dns_ms = $timer.ElapsedMilliseconds
    $result.dns_address_count = $answers.Count
    if ($answers.Count -gt 0) {
        $result.dns_ok = $true
        # Use IPv4 unless the only way out is IPv6 (an IPv6-only network).
        $ipv4 = @($answers | Where-Object { $_.Type -eq 'A' })
        $ipv6 = @($answers | Where-Object { $_.Type -eq 'AAAA' })
        if (($hasIPv6Route -and -not $hasIPv4Route -and $ipv6.Count -gt 0) -or $ipv4.Count -eq 0) {
            $address = $ipv6[0].IPAddress
            $result.tcp_family = 'IPv6'
        } else {
            $address = $ipv4[0].IPAddress
            $result.tcp_family = 'IPv4'
        }
    } else {
        $result.dns_error = 'No address records were returned.'
    }
} catch {
    $result.dns_error = $_.Exception.Message
    if ($_.Exception.NativeErrorCode) { $result.dns_error_code = [int]$_.Exception.NativeErrorCode }
}

# 3. Can the PC open a TCP connection to port 443 (HTTPS)? Connect, then close. No data is sent.
if ($address) {
    $ip = [System.Net.IPAddress]::Parse($address)
    $client = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $connect = $client.ConnectAsync($ip, 443)
        if ($connect.Wait(5000)) {
            $result.tcp_ok = $client.Connected
            $result.tcp_ms = $timer.ElapsedMilliseconds
        } else {
            $result.tcp_ok = $false
            $result.tcp_error = 'TimedOut'
        }
    } catch {
        $result.tcp_ok = $false
        $base = $_.Exception.GetBaseException()
        if ($base -is [System.Net.Sockets.SocketException]) {
            $result.tcp_error = [string]$base.SocketErrorCode
        } else {
            $result.tcp_error = 'Other'
        }
    } finally {
        $client.Dispose()
    }
}

ConvertTo-TechDeskJson ([pscustomobject]$result)
"""

# Friendly wording for common failures. PowerShell returns codes, not
# sentences, so the wording is the same on every Windows language.
DNS_ERROR_TEXT = {
    9003: "the DNS server says the name does not exist",
    9002: "the DNS server reported a failure",
    1460: "no answer from the DNS server in time",
    9501: "the DNS server returned no address records",
    11001: "the name could not be found",
}
TCP_ERROR_TEXT = {
    "TimedOut": "no response within 5 seconds",
    "ConnectionRefused": "the connection was refused",
    "NetworkUnreachable": "the network is unreachable",
    "HostUnreachable": "the server is unreachable",
    "AccessDenied": "the connection was blocked (possibly by a firewall or security software)",
}


def parse_network(raw: Any, checked_at: datetime) -> CheckResult:
    """Turn the Network Check JSON into a CheckResult."""
    raw = _require_dict(raw)

    tcp_raw = raw.get("tcp_ok")
    dns_ok = raw.get("dns_ok") is True
    gateway_error = _clean_text(raw.get("gateway_error"))
    adapters_up = _non_negative_int(raw.get("adapters_up"))
    physical_up = _optional_int(raw.get("physical_up"))
    tcp_family = _clean_text(raw.get("tcp_family"))
    data = NetworkData(
        adapters_up=adapters_up,
        physical_up=physical_up if physical_up is not None and physical_up >= 0 else adapters_up,
        gateway_found=raw.get("gateway_found") is True,
        gateway_ping=raw.get("gateway_ping") if isinstance(raw.get("gateway_ping"), bool) else None,
        dns_ok=dns_ok,
        tcp_ok=tcp_raw if isinstance(tcp_raw, bool) and dns_ok else None,
        interface_aliases=tuple(_clean_text(a) for a in as_list(raw.get("interface_aliases")) if _clean_text(a)),
        dns_problem=None if dns_ok else _dns_problem(raw),
        tcp_problem=_tcp_problem(raw) if dns_ok and tcp_raw is False else None,
        dns_ms=_optional_int(raw.get("dns_ms")),
        tcp_ms=_optional_int(raw.get("tcp_ms")),
        gateway_problem="adapter information could not be read" if gateway_error else None,
        tcp_family=tcp_family if tcp_family in ("IPv4", "IPv6") else None,
    )
    status, summary, notes = interpret_network(data)

    # Raw Windows error text is shown in the window only. It is never copied
    # into the ticket note, because it can contain names or addresses.
    dns_detail = _clean_text(raw.get("dns_error"))
    if not dns_ok and dns_detail and _optional_int(raw.get("dns_error_code")) not in DNS_ERROR_TEXT:
        notes.append(f"DNS error reported by Windows: {dns_detail}")
    if gateway_error:
        notes.append(f"Network adapter details could not be read: {gateway_error}")

    if data.gateway_found:
        via = f" (via {', '.join(data.interface_aliases)})" if data.interface_aliases else ""
        gateway_text = f"Yes{via}"
    elif data.gateway_problem:
        gateway_text = "Could not check"
    else:
        gateway_text = "No"

    rows = [
        ("Active connection with a default gateway", gateway_text),
        (f"DNS lookup of {DNS_TEST_NAME}", _pass_fail(data.dns_ok, data.dns_ms, data.dns_problem)),
        (f"TCP connection to {DNS_TEST_NAME}:{TCP_TEST_PORT}", _tcp_text(data)),
        ("Gateway ping (for information only)", _ping_text(data.gateway_ping)),
    ]
    return CheckResult("Network Check", checked_at, status, summary, rows, notes, data)


def interpret_network(data: NetworkData) -> tuple[str, str, list[str]]:
    """Decide the overall network status.

    The decision uses the gateway, DNS and TCP 443 results. The gateway ping
    is only extra information and never makes the status worse on its own.
    """
    notes: list[str] = []

    if data.dns_ok and data.tcp_ok:
        status = OK
        summary = f"Basic internet access works: DNS lookup and an HTTPS (port {TCP_TEST_PORT}) connection both succeeded."
        if not data.gateway_found and not data.gateway_problem:
            notes.append(
                "No default gateway was reported even though the internet tests passed. "
                "This can happen with some VPN or proxy setups."
            )
    elif is_offline(data):
        status = REVIEW
        summary = "No Wi-Fi or Ethernet adapter is connected, so the PC appears to be offline."
        notes.append("Check Wi-Fi, airplane mode, the network cable, and that the network adapter is enabled.")
        if data.adapters_up > data.physical_up:
            notes.append(
                "Virtual adapters (for example from VMware, Hyper-V or WSL) are connected, "
                "but they do not reach the internet on their own."
            )
    elif not data.gateway_found:
        status = REVIEW
        summary = (
            "No active connection has a default gateway, so the PC has no route to the internet."
            if not data.gateway_problem
            else "The network adapter information could not be read."
        )
        if not data.dns_ok:
            notes.append("The DNS lookup also failed.")
    elif not data.dns_ok:
        status = REVIEW
        summary = f"DNS problem: a default gateway exists, but {DNS_TEST_NAME} could not be looked up."
        notes.append("The HTTPS test was skipped because there was no address to connect to.")
    else:
        status = REVIEW
        summary = (
            f"DNS works, but the HTTPS (port {TCP_TEST_PORT}) connection failed. A firewall, "
            "proxy, VPN or upstream issue may be blocking web traffic."
        )
        notes.append(
            "This test connects directly and does not use proxy settings. On networks that "
            "require a proxy it can fail even when web browsing works."
        )

    if data.gateway_ping is False:
        notes.append(PING_NO_REPLY_NOTE)
    return status, summary, notes


def is_offline(data: NetworkData) -> bool:
    """No physical adapter is connected and there is no default gateway."""
    return data.physical_up == 0 and not data.gateway_found and not data.gateway_problem


def _dns_problem(raw: dict) -> str:
    """A fixed, safe phrase. Raw error text is shown separately, in the window only."""
    code = _optional_int(raw.get("dns_error_code"))
    return DNS_ERROR_TEXT.get(code, "the lookup failed")


def _tcp_problem(raw: dict) -> str:
    code = _clean_text(raw.get("tcp_error"))
    return TCP_ERROR_TEXT.get(code, "the connection failed")


def _pass_fail(ok: bool, ms: int | None, problem: str | None) -> str:
    if ok:
        return f"OK ({ms} ms)" if ms is not None else "OK"
    return f"Failed: {problem}" if problem else "Failed"


def _tcp_text(data: NetworkData) -> str:
    if data.tcp_ok is None:
        return "Not tested (DNS lookup failed)"
    family = data.tcp_family
    if data.tcp_ok:
        details = [f"{data.tcp_ms} ms"] if data.tcp_ms is not None else []
        details += [family] if family else []
        return f"OK ({', '.join(details)})" if details else "OK"
    over = f" over {family}" if family else ""
    return f"Failed{over}: {data.tcp_problem}" if data.tcp_problem else f"Failed{over}"


def _ping_text(ping: bool | None) -> str:
    if ping is True:
        return "Replied"
    if ping is False:
        return "No reply (not proof of an outage)"
    return "Not tested"


def run_network_check() -> CheckResult:
    return _run_check("Network Check", NETWORK_SCRIPT, NETWORK_TIMEOUT, parse_network)


# ---------------------------------------------------------------------------
# Recent Errors
# ---------------------------------------------------------------------------

EVENTS_SCRIPT = r"""
$days = 7
$perLog = 20
# Level 2 = Error. timediff is how many milliseconds ago the event was logged.
$xpath = '*[System[(Level=2) and TimeCreated[timediff(@SystemTime) <= ' + ($days * 86400000) + ']]]'
$events = @()
$logErrors = @()

foreach ($logName in @('System', 'Application')) {
    try {
        # -FilterXPath is used instead of -FilterHashtable on purpose: with
        # -FilterHashtable, a log you may not read reports 'no events found'
        # instead of 'access denied', so a permission problem would look like
        # a clean log. The newest events come first.
        $found = @(Get-WinEvent -LogName $logName -FilterXPath $xpath -MaxEvents $perLog -ErrorAction Stop)
        # Only the time, log, source and Event ID leave PowerShell. The event
        # message text is never copied into the output.
        foreach ($e in $found) {
            if ($null -eq $e.TimeCreated) { continue }
            $events += [pscustomobject]@{
                time     = $e.TimeCreated.ToString('yyyy-MM-ddTHH:mm:sszzz', [System.Globalization.CultureInfo]::InvariantCulture)
                log      = $e.LogName
                provider = $e.ProviderName
                event_id = $e.Id
            }
        }
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }
        $logErrors += [pscustomobject]@{ log = $logName; kind = (Get-ErrorKind $_); message = $_.Exception.Message }
    }
}

ConvertTo-TechDeskJson ([pscustomobject]@{
    days          = $days
    per_log_limit = $perLog
    events        = @($events)
    log_errors    = @($logErrors)
})
"""


def parse_events(raw: Any, checked_at: datetime) -> CheckResult:
    """Turn the Recent Errors JSON into a CheckResult (newest first, at most 20)."""
    raw = _require_dict(raw)
    days = _non_negative_int(raw.get("days")) or EVENT_DAYS
    per_log_limit = _non_negative_int(raw.get("per_log_limit")) or MAX_EVENTS

    parsed: list[EventRecord] = []
    for item in as_list(raw.get("events")):
        record = _parse_event(item)
        if record is not None:
            parsed.append(record)
    parsed.sort(key=lambda e: e.time, reverse=True)
    per_log = Counter(e.log for e in parsed)
    possibly_more = len(parsed) > MAX_EVENTS or any(n >= per_log_limit for n in per_log.values())
    events = tuple(parsed[:MAX_EVENTS])

    notes: list[str] = []
    unreadable: list[str] = []
    denied: list[str] = []
    for item in as_list(raw.get("log_errors")):
        if not isinstance(item, dict):
            continue
        log = _clean_text(item.get("log")) or "A log"
        unreadable.append(log)
        if item.get("kind") == "access_denied":
            denied.append(log)
            notes.append(f"The {log} log could not be read with standard permissions.")
        else:
            detail = _clean_text(item.get("message"))
            notes.append(f"The {log} log could not be read" + (f": {detail}" if detail else "."))

    data = EventsData(
        events=events,
        days=days,
        possibly_more=possibly_more,
        unreadable_logs=tuple(unreadable),
        access_denied_logs=tuple(denied),
    )
    shown = Counter(e.log for e in events)

    if data.nothing_read:
        status = FAILED
        summary = "Neither the System nor the Application log could be read."
    elif events:
        status = REVIEW
        breakdown = ", ".join(f"{log}: {count}" for log, count in sorted(shown.items()))
        if possibly_more:
            summary = f"Showing the {len(events)} most recent Error events from the last {days} days ({breakdown}). There may be more."
        else:
            summary = f"{len(events)} Error event{'s' if len(events) != 1 else ''} in the last {days} days ({breakdown})."
        notes.insert(0, EVENT_DISCLAIMER)
    elif unreadable:
        status = REVIEW
        summary = f"No Error events found in the logs that could be read (last {days} days)."
    else:
        status = OK
        summary = f"No Error events in the System or Application logs in the last {days} days."
        notes.append(
            "No errors logged does not guarantee there is no problem. Some issues are not "
            "written to these logs."
        )

    rows = [("Logs checked", f"System and Application, Error level, last {days} days")]
    return CheckResult("Recent Errors", checked_at, status, summary, rows, notes, data)


def _parse_event(item: Any) -> EventRecord | None:
    """One event, or None if the entry is incomplete (bad entries are skipped, not fatal)."""
    if not isinstance(item, dict):
        return None
    try:
        when = datetime.fromisoformat(str(item.get("time")))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.astimezone()  # treat a time without an offset as local time
    event_id = item.get("event_id")
    if isinstance(event_id, bool) or not isinstance(event_id, int):
        return None
    log = _clean_text(item.get("log")) or "Unknown"
    provider = _clean_text(item.get("provider")) or "Unknown source"
    return EventRecord(time=when, log=log, provider=provider, event_id=event_id)


def run_recent_errors() -> CheckResult:
    return _run_check("Recent Errors", EVENTS_SCRIPT, EVENTS_TIMEOUT, parse_events)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def now_local() -> datetime:
    """The current local time, including the UTC offset."""
    return datetime.now().astimezone()


def failed_result(title: str, message: str, checked_at: datetime | None = None) -> CheckResult:
    """A result for a check that could not run at all."""
    return CheckResult(
        title=title,
        checked_at=checked_at or now_local(),
        status=FAILED,
        summary=message,
        rows=[],
        notes=["Nothing was changed on this PC. You can safely run the check again."],
        data=None,
    )


def _run_check(
    title: str,
    script: str,
    timeout: float,
    parse: Callable[[Any, datetime], CheckResult],
) -> CheckResult:
    checked_at = now_local()
    try:
        raw = run_powershell_json(script, timeout=timeout)
        return parse(raw, checked_at)
    except DiagnosticError as exc:
        return failed_result(title, str(exc), checked_at)


def as_list(value: Any) -> list:
    """Always return a list.

    Windows PowerShell 5.1 can send a single item as a plain object instead
    of a one-item list. It can also wrap a list as {"value": [...], "Count": n}.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get("value"), list) and "Count" in value:
        return value["value"]
    return [value]


def _require_dict(raw: Any) -> dict:
    if not isinstance(raw, dict):
        raise DiagnosticError("PowerShell returned results in an unexpected format, so they could not be read.")
    return raw


def _error_parts(raw: dict) -> list[tuple[str, str, str]]:
    parts = []
    for item in as_list(raw.get("errors")):
        if isinstance(item, dict):
            parts.append((
                _clean_text(item.get("part")) or "unknown",
                _clean_text(item.get("message")),
                _clean_text(item.get("kind")) or "other",
            ))
    return parts


_PART_NAMES = {"windows": "Windows version", "ram": "RAM", "disk": "Disk space"}


def _partial_failure_note(part: str, message: str, kind: str) -> str:
    name = _PART_NAMES.get(part, part)
    if kind == "access_denied":
        return f"{name}: {PERMISSION_MESSAGE}"
    return f"{name} could not be read" + (f": {message}" if message else ".")


def _clean_text(value: Any) -> str:
    """A tidy one-line string, or '' for missing values."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    return " ".join(str(value).split())


def _positive_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value > 0 else None


def _non_negative_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value >= 0 else None


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _non_negative_int(value: Any) -> int:
    number = _optional_int(value)
    return number if number is not None and number >= 0 else 0
