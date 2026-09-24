# TechDesk Snapshot

A small Windows desktop app for the first few minutes of a support ticket. It collects basic facts about a PC and turns them into a short, privacy-safe **ticket note** that you can paste into a helpdesk system.

It combines ideas from my earlier PowerShell projects into one tool a technician can use:

| Earlier project | Becomes this check |
| --- | --- |
| PC inventory script | **PC Health**: Windows version, installed RAM, and free space on the system drive |
| Network checker script | **Network Check**: default gateway, DNS lookup, and a TCP connection to port 443 |
| Event log script | **Recent Errors**: recent Error events from the System and Application logs |

> *(Add links to those three repositories here once they are public.)*

Built with **Python 3.11+ and Tkinter**, which come with Python, plus **Windows PowerShell 5.1**, which comes with Windows. There is nothing extra to install with pip.

---

## What it looks like

The window has five buttons: **PC Health**, **Network Check**, **Recent Errors**, **Run All** and **Copy Ticket Note**. Each check has a tab with a coloured status badge, the key facts, and a plain-English explanation. The **Ticket Note** tab shows exactly what will be copied.

> *(Screenshot placeholder. Add `docs/screenshot.png` taken on a test PC or VM. Check that it does not show a real computer name or username before uploading.)*

### Sample output (fictional)

> **This sample is FICTIONAL.** It was made from invented test data. It is not from a real computer.

```text
TechDesk Snapshot - ticket note
Checks run: 2026-03-09 10:42 (UTC-05:00) to 2026-03-09 10:43 (UTC-05:00)

PC HEALTH - Review (checked 10:42)
- Windows: Microsoft Windows 11 Pro, version 24H2 (build 26100.4652), 64-bit
- Installed RAM: 8 GB
- System drive (C:): 18.2 GB free of 237.5 GB (8% free)
- Finding: free disk space is low.

NETWORK CHECK - OK (checked 10:42)
- Active connection with a default gateway: Yes
- DNS lookup of example.com: OK
- HTTPS connection (TCP 443) to example.com: OK over IPv4
- Gateway ping: No reply (for information only: many routers ignore ping, so this is not proof of an outage)
- Result: Basic internet access works: DNS lookup and an HTTPS (port 443) connection both succeeded.

RECENT ERRORS - Review (checked 10:43)
- 5 Error events in the last 7 days (Application: 3, System: 2)
- Most recent: 2026-03-09 09:58, Application, Application Error, Event ID 1000
- Most frequent (source, Event ID, count):
    Application Error, Event ID 1000: 3
    Service Control Manager, Event ID 7000: 1
    Microsoft-Windows-DistributedCOM, Event ID 10016: 1
- An event on its own does not prove what caused a problem.

SUGGESTED NEXT CHECKS
- Confirm the exact symptom, when it started, and whether other users or devices are affected.
- Free space is low. Review Settings > System > Storage with the user before removing anything.
- Application Error Event ID 1000 appears 3 times. Look it up and check whether its times match the reported problem.
- In Event Viewer, compare the listed event times with when the user saw the problem.

Read-only snapshot: nothing was changed on the PC. Computer name, username, IP addresses and event message text are intentionally left out.
```

The sample shows two deliberate choices:

- The gateway did not answer ping, yet the network status is **OK**, because DNS and HTTPS both worked. A missing ping reply on its own is never reported as an outage.
- The events are reported as **things to look at**, not as the cause of the problem.

---

## Setup (Windows 10 or 11)

### 1. Install Python 3.11 or newer

1. Go to <https://www.python.org/downloads/windows/>. python.org offers two ways to install:
   - **Python install manager** (the newer way): install it, then open PowerShell and run `py install 3.13`. Accept the offer to add Python to your PATH if you are asked.
   - **Windows installer (64-bit)** for a specific version (the classic way): on the first screen, tick **"Add python.exe to PATH"**, then click **Install Now**.

   Either way you get the `py` command, and Tkinter is included.
2. Open a **new** PowerShell window and check that it worked:

   ```powershell
   py --version
   ```

   You should see `Python 3.11` or newer. `py -m tkinter` should open a small test window, which you can close.

> If typing `python` opens the Microsoft Store, that is Windows' "app execution alias". Use `py` instead, or turn the alias off: search the Start menu for **Manage app execution aliases**. It is under Settings > Apps > Advanced app settings on Windows 11, and under Settings > Apps > Apps & features on Windows 10.

### 2. Get the project

Download or clone this repository, then open PowerShell **in the project folder** (the folder that contains `README.md`):

```powershell
cd C:\path\to\TechDeskSnapshot
```

There are no packages to install and no virtual environment is needed to run the app.

---

## Running the app

```powershell
py -m techdesk_snapshot
```

A window titled **TechDesk Snapshot** opens. Click **Run All**. The checks usually finish within a few seconds, and the window stays usable while they run. Then open the **Ticket Note** tab, or click **Copy Ticket Note** and paste into the ticket with **Ctrl+V**.

No administrator rights are needed. Run it as a normal user.

## Running the tests

```powershell
py -m unittest discover -v
```

The last line should be `OK`. There are 122 tests in six files:

| Test file | What it checks |
| --- | --- |
| `tests/test_parsing.py` | Turning PowerShell JSON into results: normal PCs, low disk space (exact limits), virtual machines, Windows 10, DNS/TCP failures, virtual network adapters, a failed ping that must *not* be treated as an outage, empty or unreadable event logs, Windows PowerShell 5.1 JSON quirks, and bad data |
| `tests/test_ticket_note.py` | Note content, suggested next checks, and redaction. Fake computer names, usernames, IP addresses and message text are planted in the results, and the tests prove none of it reaches the note. They also check that ordinary words and real event source names are not damaged |
| `tests/test_error_handling.py` | Timeouts, PowerShell missing or blocked, permission errors, locked-down PowerShell, unreadable output, and a crash inside a check. Each one must become a friendly message, never a crash |
| `tests/test_script_safety.py` | Guardrails: the PowerShell scripts must not contain commands that change anything, must not collect names or event message text, and must not contact other computers |
| `tests/test_app.py` | The window itself, driven with fake checks: Run All, Copy Ticket Note (the clipboard gets exactly the preview), copying while a check is re-running, closing the window, and that the window fits above the taskbar |
| `tests/test_windows_live.py` | Runs the real, read-only scripts on this PC and checks the shape of the results, including "no events" and a log you may not read. Windows only |

Most tests use sample data, so their results do not depend on the PC. They have been run on Windows 11. The live Windows tests and window tests skip themselves on systems where they cannot run, but the suite has not been tried on macOS or Linux.

### Checking the tests themselves (optional)

```powershell
py tools\mutation_check.py
```

This takes about 4 minutes. It copies the project to a temporary folder and makes 44 small deliberate mistakes there, one at a time. For example, it makes a failed ping count as an outage, or copies adapter names into the note. After each mistake it runs the tests. A good test suite fails every time. The script ends with `44 of 44 mutants caught.` and lists any mistake the tests missed. Your real files are never changed. This technique is called *mutation testing*.

---

## What each result means

Every check shows one of these badges:

| Badge | Meaning |
| --- | --- |
| **OK** | Nothing unusual was found. |
| **Review** | Something is worth a closer look. This is not a diagnosis. |
| **Could not check** | The check could not finish (for example a timeout or missing permission). Nothing was changed, and it is safe to run it again. |
| **Running...** | The check is collecting information right now. |
| **Not run** | The check has not been run yet. |

### PC Health

| Item | Where it comes from | How to read it |
| --- | --- | --- |
| Windows | `Win32_OperatingSystem` plus the version (e.g. 24H2) and update revision from the registry | Tells you the edition and exact build. **Windows 10** is flagged because it reached end of support on 14 October 2025 (LTSC editions are not flagged). |
| Installed RAM | Total of the memory modules (`Win32_PhysicalMemory`) | Under 8 GB gets a note, because it matters for "my PC is slow" tickets. Virtual machines often do not list modules. In that case the app shows **Usable RAM** instead and says so. |
| System drive free space | `Win32_LogicalDisk` for the system drive only (usually C:) | **Review** if under 10% or under 10 GB is free. Updates and apps can fail when the drive is nearly full. Sizes use the same 1024-based "GB" as File Explorer. |

### Network Check

| Item | How it is tested | How to read it |
| --- | --- | --- |
| Active connection with a default gateway | `Get-NetAdapter` (adapters that are **Up**) and `Get-NetRoute` (default routes `0.0.0.0/0` and `::/0`) | **No** means the PC has no route off the local network. If no *physical* adapter (Wi-Fi or Ethernet) is connected, the app says the PC appears to be offline. Virtual adapters from VMware, Hyper-V or WSL stay "Up" on their own, so they are not counted for this. |
| DNS lookup of example.com | `Resolve-DnsName` | **Failed** with a working gateway usually points to DNS settings, the DNS server, or a VPN. |
| TCP connection to example.com:443 | A TCP connection to the address DNS returned, with a 5-second limit. It connects, then closes, and sends no data. It uses IPv4, or IPv6 when that is the PC's only way out, and the result says which. | **Failed** after DNS worked suggests a firewall, proxy, VPN or upstream problem. |
| Gateway ping (for information only) | Up to two pings to the IPv4 default gateway | **This never decides the result.** Many routers ignore ping on purpose, so "No reply" alone is **not** proof of an outage. |

The overall result is based on the gateway, DNS and TCP 443 results together. For example, if DNS and HTTPS both work, the result is **OK** even when the ping gets no reply.

### Recent Errors

- Shows at most **20** events at **Error** level from the local **System** and **Application** logs in the **last 7 days**, newest first.
- For each event: **time, log, source (provider) and Event ID**. The event message text is left out.
- If there may be more than 20, the app says so. The ticket note then describes the list as "the 20 most recent", not as the whole week.
- If a log cannot be read, the app says so, in the window and in the note. It never shows that as "no errors".
- **An event on its own does not prove what caused a problem.** Windows logs many harmless errors, and some repeat every day. Use the list to find events whose *times match the user's problem*, then look up the source and Event ID.
- "No Error events" is good news, but it does not guarantee there is no problem.

### Copy Ticket Note

Copies a short summary containing the time of the checks, each result, and suggested next checks. The **Ticket Note** tab shows exactly what will be copied. A check that is running again is listed as "Not run" until it finishes, so old and new results are never mixed. Read the note before pasting, as you would with anything you put into a ticket.

---

## Privacy and safety

**Read-only by design.** The app only reads information. It does not:

- change settings, the PowerShell execution policy, or any files
- ask for administrator rights
- scan or query other computers
- collect passwords or credentials
- delete anything
- try to "fix" anything automatically

**What it collects:** only the facts listed above. Each PowerShell script outputs just those fields as one line of JSON, and the Windows (CIM) queries ask only for the properties they need, for example `Get-CimInstance -Property Caption, Version, ...`.

**What never leaves PowerShell:** the computer name, the username, and event message text. Windows may load them in memory while answering a query, but the scripts never output them. The gateway address is used only inside PowerShell for the ping and is never printed or shown. The app itself reads the computer name and username from Windows in memory, but only so it can remove them from the ticket note. They are never shown, copied or saved.

**Network traffic it creates:** one DNS lookup for `example.com`, one TCP connection to `example.com` on port 443 (opened and closed immediately, no data sent), and up to two pings to your own default gateway.

**Nothing is saved.** Results stay in memory while the window is open. There are no log files. Text reaches the clipboard only when you click **Copy Ticket Note**. When you close the window, any check that is still running is stopped.

**The ticket note is protected in two ways:**

1. **Allowlist.** The note is built only from specific, known-safe fields. Raw error messages, adapter names and the explanations shown in the window are never copied into it.
2. **Safety net.** Values that came from Windows (such as event source names) are checked for this PC's computer name, username and domain. The whole note is then scanned for common forms of IP addresses (IPv4 and IPv6), MAC addresses, email addresses, and user-folder or network paths. Anything found is replaced with `[redacted]`. Generic account names such as "User" or "Administrator" are not treated as private, so they do not damage ordinary words or real names like *Microsoft-Windows-User Profiles Service*.

**How PowerShell is run.** Python starts `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` directly with `subprocess` and `shell=False`, using `-NoProfile -NonInteractive -Command <fixed script>`. The scripts are fixed text in `checks.py`. Nothing the user types is added to them. The commands are readable in the source code, not hidden or encoded.

---

## Limitations

- Windows 10/11 only. It needs the built-in Windows PowerShell 5.1.
- On PCs where security policy (AppLocker or WDAC) runs PowerShell in **Constrained Language Mode**, the checks cannot run. The app says so clearly. It does not try to get around the policy.
- It takes a single snapshot. It does not monitor the PC over time.
- **DNS** can answer from Windows' local cache, so a DNS problem that started in the last few minutes may not show yet.
- The **TCP 443 test connects directly** and does not use proxy settings. On networks that require a web proxy it can fail even though browsing works.
- Only **Error** level events are listed, not Critical or Warning. For example, *Kernel-Power 41* (an unexpected shutdown) is logged as Critical, so it will not appear in version 1.
- It does not look at Wi-Fi signal strength, VPN status, proxy configuration, or other drives.
- An IPv6-only gateway is detected, but it is not pinged.
- The redaction safety net catches common formats. It is a backup, not a guarantee, so **always read a note before sharing it.**
- The packaged `.exe` is not code-signed, so Windows SmartScreen may warn about it.

---

## How it works

```text
 Button click (main thread)
        |
        v
 background thread --> powershell.exe -NoProfile -NonInteractive -Command <fixed read-only script>
        |                        |
        |                        v
        |              one line of JSON on stdout
        v
 parse_* function (checks.py) --> CheckResult (status, summary, rows, notes, typed data)
        |
        v
 queue --> main thread checks it every 100 ms --> updates the window and the Ticket Note preview
```

Design decisions:

- **Structured output, not screen-scraping.** Each script prints JSON. Console text changes between Windows versions and languages, but JSON field names do not. Non-English characters are sent as `\uXXXX` escape codes, so the output cannot be garbled by the console's code page.
- **Background threads plus a queue.** Tkinter is not thread-safe, so the worker threads never touch, or even hold a reference to, the window. The main thread checks for finished results 10 times a second, and the window never freezes.
- **Timeouts everywhere:** 30 s for PC Health, 45 s for Network Check, 60 s for Recent Errors. Inside the network script, the ping waits 1 s and the TCP connection waits 5 s. A check that hangs is stopped and reported, and closing the window stops any check still running.
- **Codes, not messages, in the ticket note.** Windows' TCP error *message* can contain the server's IP address, so for the HTTPS test the script returns only the error *code* (`ConnectionRefused`, `TimedOut`) and the app turns it into plain English. DNS and adapter error text from Windows is shown in the window to help the technician, but it is never copied into the note.
- **`-FilterXPath`, not `-FilterHashtable`, for the event logs.** While testing, I found that `Get-WinEvent -FilterHashtable` reports a log you are not allowed to read as "no events found". That would turn a permission problem into a clean-looking result. `-FilterXPath` reports it as "access denied".

```text
TechDeskSnapshot/
├── techdesk_snapshot/
│   ├── __init__.py            # app name and version
│   ├── __main__.py            # lets "py -m techdesk_snapshot" start the app
│   ├── app.py                 # the Tkinter window, buttons, tabs, background threads
│   ├── checks.py              # the three PowerShell scripts + parsing + plain-English results
│   ├── powershell.py          # runs PowerShell safely (shell=False, timeouts, error messages)
│   └── ticket_note.py         # builds and redacts the ticket note, suggests next checks
├── tests/
│   ├── __init__.py            # marks tests/ as a package so unittest can find the tests
│   ├── test_app.py
│   ├── test_error_handling.py
│   ├── test_parsing.py
│   ├── test_script_safety.py
│   ├── test_ticket_note.py
│   └── test_windows_live.py
├── tools/
│   └── mutation_check.py      # optional: checks that the tests catch deliberate mistakes
├── .gitignore
└── README.md
```

---

## Verify it on your own PC (checklist)

1. `py -m unittest discover -v` ends with `OK`.
2. `py -m techdesk_snapshot` opens the window. Click **Run All**. All three badges change from *Running...* to a result within about 15 seconds, and you can switch tabs while they run.
3. **PC Health** matches **Settings > System > About** (Windows edition, version, RAM) and File Explorer (free space on C:).
4. **Network Check** shows OK on a working connection. Then, sitting at the PC (not over remote access), **unplug the network cable and turn Wi-Fi off**. Airplane mode alone does not disconnect a cable. Run Network Check again. It should report no default gateway or that the PC appears to be offline, with no crash. Reconnect afterwards.
5. **Recent Errors**: open **Event Viewer > Windows Logs**, then look at **System** and **Application**, each filtered to *Error*. The app's System rows should match the newest System errors, and its Application rows the newest Application errors.
6. Click **Copy Ticket Note**, paste into Notepad, and confirm there is no computer name, username or IP address.
7. Close the app and check the project folder. The only new items should be Python's `__pycache__` folders (compiled code, not results, and already in `.gitignore`). The app writes no results, logs or notes to disk.

---

## Optional: package as a Windows .exe

This step is optional and uses [PyInstaller](https://pyinstaller.org/). It builds a program you can run on PCs without Python. Run these commands in PowerShell, in the project folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip pyinstaller
.\.venv\Scripts\python.exe -m PyInstaller --noconsole --onefile --name TechDeskSnapshot --paths . techdesk_snapshot\__main__.py
```

- The app appears at `dist\TechDeskSnapshot.exe`.
- `--noconsole` hides the black console window, and `--onefile` packs everything into one `.exe`.
- The commands call `.venv\Scripts\python.exe` directly instead of "activating" the virtual environment, because activation runs a `.ps1` script that the default execution policy blocks. This avoids touching the execution policy.
- The `.exe` is **unsigned**, so SmartScreen may show "Windows protected your PC" (click *More info*, then *Run anyway*, only for your own build). Some antivirus tools also flag one-file PyInstaller apps.
- Building with `--onedir` instead of `--onefile` starts faster and is flagged less often. The app is then `dist\TechDeskSnapshot\TechDeskSnapshot.exe`, next to an `_internal` folder. Zip and share the **whole** `dist\TechDeskSnapshot` folder, because the `.exe` alone will not run.
- Do **not** commit `build\`, `dist\` or `*.spec` (they are in `.gitignore`). To share the app, attach it to a **GitHub Release**.

---

## Talking about this project in an interview

**30-second version:**

> "TechDesk Snapshot is a small Windows app I built for the start of a support ticket. With one click it checks the Windows version, RAM and disk space, basic network connectivity, and recent Error events, then produces a ticket note I can paste into the helpdesk system. I built it in Python with Tkinter, and it runs read-only PowerShell commands in the background, so the window never freezes. I paid special attention to privacy: the note leaves out computer names, usernames, IP addresses and event messages, and I wrote tests to prove it."

**Points worth highlighting:**

- **Troubleshooting judgement is built into the wording.** A failed gateway ping is shown as information only, because many routers block ping. An Error event is treated as a lead to follow, not a cause.
- **Safe by default.** Everything is read-only, needs no admin rights, never touches the execution policy, and saves nothing. That makes it safe to run on a user's PC while they watch.
- **Real Windows behaviour, found by testing.**
  - `Get-WinEvent -FilterHashtable` hides "access denied" as "no events", so I used `-FilterXPath`.
  - Virtual adapters from VMware or WSL stay "Up" when the PC is offline, so only physical adapters decide "offline".
  - Windows PowerShell 5.1 turns one-item lists into single values and garbles non-English characters, so the JSON is handled with care.
- **Testing.** 122 automated tests cover parsing, redaction, error handling, the window's behaviour, and "guardrail" tests that fail if a script ever gains a command that changes the PC. A mutation-testing script (`tools\mutation_check.py`) plants 44 deliberate bugs and confirms the tests catch every one. *Run it yourself before an interview so you can describe what you saw.*

**Questions you might be asked:**

- *Why not use `Test-NetConnection`?* When the port can't be reached, it can take 20+ seconds to give up and prints progress text. A TCP connection with a 5-second limit gives the same answer faster and more predictably.
- *Why doesn't a failed ping mean the network is down?* ICMP (ping) is often blocked by routers and firewalls. DNS and an HTTPS connection are better evidence that the PC can reach the internet.
- *How does the window stay responsive?* Each check runs in a background thread. Tkinter is not thread-safe, so results go through a queue that the main thread checks every 100 ms.
- *What would you add next?* Critical-level events such as Kernel-Power 41, a proxy-aware web test, an "Export note to file" button that only runs when the user clicks it, and a signed installer.

**Resume bullet:**

> Built *TechDesk Snapshot*, a Python/Tkinter Windows tool that runs read-only PowerShell diagnostics (system info, network connectivity, Event Log errors) in background threads and produces a privacy-redacted helpdesk ticket note; covered parsing, redaction, failure handling and UI behaviour with 122 unit tests, checked with a mutation-testing script.
