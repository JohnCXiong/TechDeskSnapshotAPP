"""Tests for the window's behaviour: Run All, Copy Ticket Note, re-runs, closing.

A real (hidden) Tkinter window is created, but the checks are replaced with
quick fakes, so no PowerShell runs. The tests skip themselves on machines
without Tkinter or a display.
"""

import gc
import threading
import time
import unittest
from unittest import mock

from techdesk_snapshot.checks import OK, parse_events, parse_network, parse_pc_health
from tests.test_parsing import CHECKED_AT, event, network_sample, pc_sample

from techdesk_snapshot import powershell

try:
    import tkinter as tk

    from techdesk_snapshot import app as app_module
except ImportError:  # tkinter missing (some Linux installs)
    tk = None


@unittest.skipIf(tk is None, "tkinter is not available")
class WindowPlacementTests(unittest.TestCase):
    """The window must fit above the taskbar so the status bar is always visible."""

    def test_window_fits_inside_the_work_area(self):
        cases = (
            ((0, 0, 1366, 728), 1.0),  # small laptop, taskbar at the bottom
            ((0, 0, 1920, 1032), 1.5),  # 1080p laptop at 150%
            ((0, 0, 2560, 1392), 1.0),  # big monitor: normal size
            ((0, 48, 1920, 1032), 1.0),  # taskbar at the top
        )
        for area, scale in cases:
            with self.subTest(area=area, scale=scale):
                left, top, area_w, area_h = area
                width, height, x, y = app_module.fit_window(area, scale)
                title_bar = int(35 * scale)
                self.assertLessEqual(y + title_bar + height, top + area_h)
                self.assertGreaterEqual(x, left)
                self.assertLessEqual(x + width, left + area_w)
                self.assertLessEqual(width, int(960 * scale))
                self.assertLessEqual(height, int(700 * scale))

    def test_normal_size_on_a_big_screen(self):
        self.assertEqual(app_module.fit_window((0, 0, 2560, 1392), 1.0)[:2], (960, 700))


def fake_checks(network_gate=None):
    """Quick stand-ins for the three checks. network_gate lets a test hold Network Check 'running'."""

    def pc():
        return parse_pc_health(pc_sample(), CHECKED_AT)

    def network():
        if network_gate is not None:
            network_gate.wait(10)
        raw = network_sample(interface_aliases=["jdoe's Wi-Fi"], gateway_ping=False)
        return parse_network(raw, CHECKED_AT)

    def events():
        return parse_events({"days": 7, "events": [event("2026-09-23T09:15:00-07:00")]}, CHECKED_AT)

    return {"pc": ("PC Health", pc), "network": ("Network Check", network), "events": ("Recent Errors", events)}


@unittest.skipIf(tk is None, "tkinter is not available")
class AppTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError:
            self.skipTest("no display available")
        self.root.withdraw()
        self.copied = []
        self.root.clipboard_clear = lambda: self.copied.clear()
        self.root.clipboard_append = lambda text: self.copied.append(text)
        self.gate = threading.Event()
        self.app = None
        # Closing the window sets a "stopping" flag in powershell.py; put it back afterwards.
        patcher = mock.patch.object(powershell, "_stopping", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.gate.set()
        try:
            if self.app is not None:
                self.app.close()
            else:
                self.root.destroy()
        except tk.TclError:
            pass  # already closed by the test
        # Free the closed window now, on the main thread. Tkinter must never
        # be cleaned up by one of the background check threads.
        self.app = self.root = None
        gc.collect()

    def make_app(self, gate=None):
        patcher = mock.patch.dict(app_module.CHECKS, fake_checks(gate))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.app = app_module.TechDeskApp(self.root)
        return self.app

    def pump(self, app, until, timeout=10):
        deadline = time.time() + timeout
        while not until() and time.time() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertTrue(until(), "the window did not finish in time")

    def test_run_all_runs_every_check_and_fills_the_window(self):
        app = self.make_app()
        app.run_all()
        self.assertEqual(app.running, {"pc", "network", "events"})
        self.assertTrue(app.run_all_button.instate(["disabled"]))
        self.pump(app, lambda: not app.running)
        self.assertEqual(set(app.results), {"pc", "network", "events"})
        self.assertEqual(app.results["pc"].status, OK)
        self.assertEqual(len(app.event_table.get_children()), 1)
        self.assertFalse(app.run_all_button.instate(["disabled"]))
        self.assertIn("Finished at", app.status.cget("text"))

    def test_copy_puts_exactly_the_preview_on_the_clipboard_without_private_details(self):
        app = self.make_app()
        app.run_all()
        self.pump(app, lambda: not app.running)
        app.copy_ticket_note()
        self.assertEqual(len(self.copied), 1)
        note = self.copied[0]
        self.assertTrue(note.startswith("TechDesk Snapshot - ticket note"))
        self.assertEqual(note, app.note_text.get("1.0", "end-1c"))
        self.assertNotIn("Wi-Fi", note)  # adapter names are shown in the window only
        self.assertIn("Ticket note copied", app.status.cget("text"))

    def test_copy_during_a_rerun_does_not_include_the_old_result(self):
        app = self.make_app(gate=self.gate)
        self.gate.set()
        app.run_all()
        self.pump(app, lambda: not app.running)
        self.gate.clear()
        app.start_check("network")  # held "running" by the gate
        self.assertNotIn("network", app.results)
        app.copy_ticket_note()
        self.assertIn("NETWORK CHECK - Not run", self.copied[0])
        self.assertIn("still running show as Not run", app.status.cget("text"))
        self.gate.set()
        self.pump(app, lambda: not app.running)
        self.assertIn("network", app.results)

    def test_copy_before_any_result_explains_instead_of_copying(self):
        app = self.make_app(gate=self.gate)
        with mock.patch.object(app_module.messagebox, "showinfo") as showinfo:
            app.copy_ticket_note()
            self.assertIn("Run at least one check first", showinfo.call_args.args[1])
            app.start_check("network")
            app.copy_ticket_note()
            self.assertIn("still running", showinfo.call_args.args[1])
        self.assertEqual(self.copied, [])

    def test_closing_the_window_stops_running_checks(self):
        app = self.make_app()
        with mock.patch.object(app_module, "stop_running_checks") as stop:
            app.close()
        stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
