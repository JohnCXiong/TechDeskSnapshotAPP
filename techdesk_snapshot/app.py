"""The TechDesk Snapshot window (Tkinter).

Tkinter is not thread-safe, so this file follows one rule: only the main
thread touches the window. Each check runs in a background thread so the
window stays responsive. When a check finishes, its thread puts the result
in a queue. The main thread checks that queue every 100 ms and updates
the screen.
"""

from __future__ import annotations

import gc
import queue
import threading
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable

from . import APP_NAME, __version__
from .checks import (
    EVENT_DAYS,
    FAILED,
    MAX_EVENTS,
    OK,
    REVIEW,
    CheckResult,
    EventsData,
    failed_result,
    now_local,
    run_network_check,
    run_pc_health,
    run_recent_errors,
)
from .powershell import stop_running_checks
from .ticket_note import build_ticket_note

POLL_MS = 100

# key -> (button / tab title, function that runs the check)
CHECKS: dict[str, tuple[str, Callable[[], CheckResult]]] = {
    "pc": ("PC Health", run_pc_health),
    "network": ("Network Check", run_network_check),
    "events": ("Recent Errors", run_recent_errors),
}

INTROS = {
    "pc": "Windows version, installed memory (RAM), and free space on the system drive.",
    "network": (
        "Looks for an active connection with a default gateway, looks up example.com in DNS, "
        "and opens a TCP connection to port 443 (HTTPS). The gateway ping is for information only."
    ),
    "events": (
        f"Up to {MAX_EVENTS} Error events from the System and Application logs in the last "
        f"{EVENT_DAYS} days. Only the time, log, source and Event ID are shown. Event message "
        "text is left out. An event on its own does not prove what caused a problem."
    ),
}

# Badge colours were picked to keep white text readable (at least 4.5:1 contrast).
BADGE_COLOURS = {
    OK: "#1e7b34",
    REVIEW: "#b25e09",
    FAILED: "#b3261e",
    "Running...": "#1a5fb4",
    "Not run": "#6b7280",
}


class ResultPanel(ttk.Frame):
    """One check's status badge, summary, key facts and plain-English notes."""

    def __init__(self, parent: tk.Misc, intro: str, fonts: dict[str, tkfont.Font], px: Callable[[int], int]) -> None:
        super().__init__(parent, padding=(px(16), px(12)))
        self.px = px
        self.wrap = px(700)

        self.intro = ttk.Label(self, text=intro, style="Muted.TLabel", justify="left")
        self.intro.pack(anchor="w", fill="x")

        header = ttk.Frame(self)
        header.pack(anchor="w", fill="x", pady=(px(12), px(8)))
        self.badge = tk.Label(header, font=fonts["badge"], fg="white", padx=px(10), pady=px(3))
        self.badge.pack(side="left", anchor="n")
        self.summary = ttk.Label(header, style="Summary.TLabel", justify="left")
        self.summary.pack(side="left", anchor="w", padx=(px(10), 0), fill="x", expand=True)

        self.rows = ttk.Frame(self)
        self.rows.pack(anchor="w", fill="x")
        self.rows.columnconfigure(1, weight=1)

        self.notes = ttk.Label(self, justify="left")
        self.notes.pack(anchor="w", fill="x", pady=(px(8), 0))
        self.checked = ttk.Label(self, style="Muted.TLabel")
        self.checked.pack(anchor="w", pady=(px(8), 0))

        self.bind("<Configure>", self._rewrap)
        self.show_not_run()

    def show_not_run(self) -> None:
        self._set_badge("Not run")
        self.summary.configure(text="Click the button above to run this check.")
        self._set_rows([])
        self.notes.configure(text="")
        self.checked.configure(text="")

    def show_running(self) -> None:
        self._set_badge("Running...")
        self.summary.configure(text="Collecting information. The window stays usable while this runs.")
        self._set_rows([])
        self.notes.configure(text="")
        self.checked.configure(text="")

    def show_result(self, result: CheckResult) -> None:
        self._set_badge(result.status)
        self.summary.configure(text=result.summary)
        self._set_rows(result.rows)
        self.notes.configure(text="\n".join(f"• {note}" for note in result.notes))
        self.checked.configure(text=f"Checked at {result.checked_at.strftime('%Y-%m-%d %H:%M:%S')}")

    def _set_badge(self, status: str) -> None:
        self.badge.configure(text=status, bg=BADGE_COLOURS.get(status, BADGE_COLOURS["Not run"]))

    def _value_wrap(self) -> int:
        return max(self.wrap - self.px(300), self.px(200))

    def _set_rows(self, rows: list[tuple[str, str]]) -> None:
        for child in self.rows.winfo_children():
            child.destroy()
        for index, (name, value) in enumerate(rows):
            ttk.Label(self.rows, text=f"{name}:", style="RowName.TLabel").grid(
                row=index, column=0, sticky="nw", padx=(0, self.px(12)), pady=self.px(2)
            )
            ttk.Label(self.rows, text=value, justify="left", wraplength=self._value_wrap()).grid(
                row=index, column=1, sticky="nw", pady=self.px(2)
            )

    def _rewrap(self, event: tk.Event) -> None:
        """Re-flow long text when the window is resized."""
        self.wrap = max(event.width - self.px(40), self.px(300))
        self.intro.configure(wraplength=self.wrap)
        self.summary.configure(wraplength=max(self.wrap - self.px(160), self.px(200)))
        self.notes.configure(wraplength=self.wrap)
        for child in self.rows.grid_slaves(column=1):
            child.configure(wraplength=self._value_wrap())


class TechDeskApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.results: dict[str, CheckResult] = {}
        self.running: set[str] = set()
        self.result_queue: queue.Queue[tuple[str, CheckResult]] = queue.Queue()

        # Windows display scaling (125%, 150% ...) makes text bigger, so the
        # sizes below grow by the same amount. 96 pixels per inch = 100%.
        self.scale = max(root.winfo_fpixels("1i") / 96.0, 1.0)
        width, height, x, y = fit_window(work_area(root), self.scale)
        root.title(APP_NAME)
        root.geometry(f"{width}x{height}+{x}+{y}")
        root.minsize(min(self.px(760), width), min(self.px(540), height))
        root.protocol("WM_DELETE_WINDOW", self.close)

        self.fonts = self._setup_style()
        self._build()
        self._poll_job = self.root.after(POLL_MS, self._poll_results)

    def px(self, value: int) -> int:
        """A size in pixels at 100% scaling, adjusted for this screen."""
        return int(value * self.scale)

    # ----- layout ---------------------------------------------------------

    def _setup_style(self) -> dict[str, tkfont.Font]:
        base = tkfont.nametofont("TkDefaultFont")
        base.configure(size=10)
        tkfont.nametofont("TkTextFont").configure(size=10)
        fonts = {
            "base": base,
            "title": base.copy(),
            "summary": base.copy(),
            "bold": base.copy(),
            "badge": base.copy(),
        }
        fonts["title"].configure(size=16, weight="bold")
        fonts["summary"].configure(size=11, weight="bold")
        fonts["bold"].configure(weight="bold")
        fonts["badge"].configure(size=9, weight="bold")

        style = ttk.Style(self.root)
        style.configure("Title.TLabel", font=fonts["title"])
        style.configure("Muted.TLabel", foreground="#4b5563")
        style.configure("Summary.TLabel", font=fonts["summary"])
        style.configure("RowName.TLabel", font=fonts["bold"])
        style.configure("Treeview", rowheight=int(base.metrics("linespace") * 1.6))
        return fonts

    def _build(self) -> None:
        px = self.px
        outer = ttk.Frame(self.root, padding=(px(16), px(14), px(16), px(8)))
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        subtitle = ttk.Label(
            outer,
            text="Read-only first-look checks for a support ticket. Nothing on this PC is changed, "
            "and results are not saved to disk.",
            style="Muted.TLabel",
            justify="left",
        )
        subtitle.pack(anchor="w", fill="x", pady=(px(2), px(10)))
        outer.bind("<Configure>", lambda e: subtitle.configure(wraplength=max(e.width - px(40), px(300))))

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(0, px(10)))
        self.check_buttons: dict[str, ttk.Button] = {}
        for key, (title, _run) in CHECKS.items():
            button = ttk.Button(buttons, text=title, command=lambda k=key: self.start_check(k))
            button.pack(side="left", padx=(0, px(6)))
            self.check_buttons[key] = button
        self.run_all_button = ttk.Button(buttons, text="Run All", command=self.run_all)
        self.run_all_button.pack(side="left", padx=(px(6), px(6)))
        ttk.Button(buttons, text="Copy Ticket Note", command=self.copy_ticket_note).pack(side="right")

        # The status bar is packed before the tabs, at the bottom, so it keeps
        # its space even when the window is short.
        status_bar = ttk.Frame(outer)
        status_bar.pack(side="bottom", fill="x", pady=(px(8), 0))
        self.status = ttk.Label(status_bar, text="Ready. Choose a check, or Run All.", style="Muted.TLabel")
        self.status.pack(side="left")
        ttk.Label(status_bar, text=f"v{__version__}", style="Muted.TLabel").pack(side="right")
        # Shown only while a check is running (see _update_busy).
        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=px(160))

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        self.tabs: dict[str, ttk.Frame] = {}
        self.panels: dict[str, ResultPanel] = {}
        for key, (title, _run) in CHECKS.items():
            tab = ttk.Frame(self.notebook)
            self.notebook.add(tab, text=f"  {title}  ")
            panel = ResultPanel(tab, INTROS[key], self.fonts, px)
            panel.pack(fill="x", anchor="n")
            self.tabs[key] = tab
            self.panels[key] = panel

        self._build_event_table(self.tabs["events"])
        self._build_note_tab()

    def _build_event_table(self, tab: ttk.Frame) -> None:
        px = self.px
        frame = ttk.Frame(tab, padding=(px(16), 0, px(16), px(12)))
        frame.pack(fill="both", expand=True)
        columns = ("time", "log", "provider", "event_id")
        self.event_table = ttk.Treeview(frame, columns=columns, show="headings", height=6)
        time_width = self.fonts["base"].measure("2026-09-24 14:32:00") + px(24)
        for column, heading, width, stretch in (
            ("time", "Time", time_width, False),
            ("log", "Log", px(110), False),
            ("provider", "Source (provider)", px(300), True),
            ("event_id", "Event ID", px(80), False),
        ):
            self.event_table.heading(column, text=heading, anchor="w")
            self.event_table.column(column, width=width, minwidth=px(60), stretch=stretch, anchor="w")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.event_table.yview)
        self.event_table.configure(yscrollcommand=scrollbar.set)
        # The scrollbar is packed first so it always keeps its width.
        scrollbar.pack(side="right", fill="y")
        self.event_table.pack(side="left", fill="both", expand=True)

    def _build_note_tab(self) -> None:
        px = self.px
        tab = ttk.Frame(self.notebook, padding=(px(16), px(12)))
        self.notebook.add(tab, text="  Ticket Note  ")
        explanation = ttk.Label(
            tab,
            text="This is exactly what Copy Ticket Note puts on the clipboard. The computer name, "
            "username, IP addresses and event message text are left out.",
            style="Muted.TLabel",
            justify="left",
        )
        explanation.pack(anchor="w", fill="x", pady=(0, px(8)))
        tab.bind("<Configure>", lambda e: explanation.configure(wraplength=max(e.width - px(40), px(300))))
        self.note_text = scrolledtext.ScrolledText(tab, wrap="word", height=12, font=("Consolas", 10))
        self.note_text.pack(fill="both", expand=True)
        self._refresh_note()

    # ----- running checks -------------------------------------------------

    def start_check(self, key: str, select_tab: bool = True) -> None:
        if key in self.running:
            return
        title, run = CHECKS[key]
        self.running.add(key)
        # Forget the previous result, so the note never mixes old and new results.
        self.results.pop(key, None)
        self.panels[key].show_running()
        if key == "events":
            self.event_table.delete(*self.event_table.get_children())
        if select_tab:
            self.notebook.select(self.tabs[key])
        threading.Thread(
            target=run_in_background, args=(self.result_queue, key, title, run), daemon=True
        ).start()
        self._refresh_note()
        self._update_busy()

    def run_all(self) -> None:
        for key in CHECKS:
            self.start_check(key, select_tab=False)

    def _poll_results(self) -> None:
        """Runs on the main thread every POLL_MS and shows any finished results."""
        try:
            while True:
                key, result = self.result_queue.get_nowait()
                self._show_result(key, result)
        except queue.Empty:
            pass
        finally:
            # Always check again later, even if showing a result went wrong.
            self._poll_job = self.root.after(POLL_MS, self._poll_results)

    def _show_result(self, key: str, result: CheckResult) -> None:
        self.running.discard(key)
        self.results[key] = result
        self.panels[key].show_result(result)
        if key == "events":
            self._fill_event_table(result)
        self._refresh_note()
        self._update_busy(finished=True)

    def _fill_event_table(self, result: CheckResult) -> None:
        self.event_table.delete(*self.event_table.get_children())
        if isinstance(result.data, EventsData):
            for event in result.data.events:
                self.event_table.insert(
                    "",
                    "end",
                    values=(event.time.strftime("%Y-%m-%d %H:%M:%S"), event.log, event.provider, event.event_id),
                )

    def _update_busy(self, finished: bool = False) -> None:
        for key, button in self.check_buttons.items():
            button.state(["disabled"] if key in self.running else ["!disabled"])
        self.run_all_button.state(["disabled"] if self.running else ["!disabled"])
        if self.running:
            names = ", ".join(CHECKS[k][0] for k in CHECKS if k in self.running)
            self.status.configure(text=f"Running: {names}...")
            if not self.progress.winfo_manager():  # not packed yet
                self.progress.pack(side="right", padx=(0, self.px(10)))
                self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.pack_forget()
            if finished:
                self.status.configure(
                    text=f"Finished at {now_local().strftime('%H:%M:%S')}. "
                    "Nothing was changed or saved. Use Copy Ticket Note to copy a summary."
                )

    # ----- ticket note ----------------------------------------------------

    def _current_note(self) -> str:
        return build_ticket_note(
            pc=self.results.get("pc"),
            network=self.results.get("network"),
            events=self.results.get("events"),
        )

    def _refresh_note(self) -> None:
        if self.results:
            self._show_note(self._current_note())
        elif self.running:
            self._show_note("Checks are running. The ticket note appears here when the first one finishes.")
        else:
            self._show_note("Run a check to build the ticket note.")

    def _show_note(self, text: str) -> None:
        self.note_text.configure(state="normal")
        self.note_text.delete("1.0", "end")
        self.note_text.insert("1.0", text)
        self.note_text.configure(state="disabled")

    def copy_ticket_note(self) -> None:
        if not self.results:
            message = (
                "The checks are still running. Copy the ticket note when at least one has finished."
                if self.running
                else "Run at least one check first, then copy the ticket note."
            )
            messagebox.showinfo(APP_NAME, message, parent=self.root)
            return
        note = self._current_note()
        self.root.clipboard_clear()
        self.root.clipboard_append(note)
        message = "Ticket note copied. Paste it into the ticket with Ctrl+V."
        if self.running:
            message += " Checks that are still running show as Not run."
        self.status.configure(text=message)

    def close(self) -> None:
        """Stop any check that is still running, then close the window."""
        self.root.after_cancel(self._poll_job)
        stop_running_checks()
        self.root.destroy()


def work_area(root: tk.Tk) -> tuple[int, int, int, int]:
    """The part of the screen not covered by the taskbar, as (left, top, width, height)."""
    try:
        import ctypes
        from ctypes import wintypes

        rect = wintypes.RECT()
        spi_getworkarea = 0x0030
        if ctypes.windll.user32.SystemParametersInfoW(spi_getworkarea, 0, ctypes.byref(rect), 0):
            return rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top
    except (AttributeError, OSError, ValueError):
        pass  # not Windows: assume a taskbar about 60 pixels high
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight() - 60


def fit_window(area: tuple[int, int, int, int], scale: float) -> tuple[int, int, int, int]:
    """Window size and position (width, height, x, y) that fit inside the work area.

    The height leaves room for the title bar, so the status bar at the bottom
    of the window is never hidden behind the taskbar.
    """
    left, top, area_width, area_height = area
    width = min(int(960 * scale), area_width - int(40 * scale))
    height = min(int(700 * scale), area_height - int(60 * scale))
    x = left + max((area_width - width) // 2, 0)
    y = top + int(10 * scale)
    return width, height, x, y


def run_in_background(
    results: queue.Queue, key: str, title: str, run: Callable[[], CheckResult]
) -> None:
    """Runs one check in a background thread.

    It only receives the queue, never the window, because Tkinter objects must
    only ever be used (and cleaned up) by the main thread.
    """
    try:
        result = run()
    except Exception as exc:  # a bug, not an expected failure: report it instead of crashing
        result = failed_result(title, f"Unexpected problem in the app: {type(exc).__name__}: {exc}")
    results.put((key, result))


def _enable_high_dpi() -> None:
    """Draw text sharply on high-resolution screens. This affects this app only."""
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass  # not Windows, or an older Windows version: the window just looks slightly softer


def main() -> None:
    _enable_high_dpi()
    root = tk.Tk()
    TechDeskApp(root)
    root.mainloop()
    # Free the closed window here, on the main thread. If Python freed it later
    # from a background thread, Tkinter would crash on exit.
    del root
    gc.collect()
