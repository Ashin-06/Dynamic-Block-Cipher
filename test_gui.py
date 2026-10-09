"""Exercise actual Tk widgets and asynchronous jobs; skip without a display."""
import time
import tempfile
from pathlib import Path
import unittest
import tkinter as tk
from gui import App

class GuiTests(unittest.TestCase):
    def setUp(self):
        try:
            self.app = App()
        except tk.TclError as exc:
            self.skipTest(str(exc))
        self.app.withdraw()
        self.errors = []
        self.app.report_callback_exception = lambda *args: self.errors.append(args)

    def tearDown(self):
        self.app.destroy()

    def wait_job(self):
        deadline = time.monotonic() + 20
        while self.app._busy and time.monotonic() < deadline:
            self.app.update()
            time.sleep(0.01)
        self.assertFalse(self.app._busy, "Worker timed out")
        self.assertFalse(self.errors)

    def test_text_roundtrip_whitespace_and_clear(self):
        a = self.app
        a._txt_pw.set("Password123")
        source = "  hello \n\t"
        a._txt_in.insert("1.0", source)
        a._text_encrypt()
        a._text_clear()  # Busy guard must preserve input.
        self.assertEqual(a._txt_in.get("1.0", "end-1c"), source)
        self.wait_job()
        encrypted = a._txt_out.get("1.0", "end-1c")
        a._txt_in.delete("1.0", "end")
        a._txt_in.insert("1.0", encrypted)
        a._text_decrypt()
        self.wait_job()
        self.assertEqual(a._txt_out.get("1.0", "end-1c"), source)
        a._text_clear()
        self.assertEqual(a._txt_pw.get(), "")

    def test_file_roundtrip_and_collision(self):
        a = self.app
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample"
            source.write_bytes(b"binary\x00\xff")
            a._file_pw.set("Password123")
            a._file_path.set(str(source))
            a._file_encrypt()
            self.wait_job()
            encrypted = Path(str(source)+".enc").read_bytes()
            a._file_encrypt()
            self.wait_job()
            self.assertEqual(Path(str(source)+".enc").read_bytes(), encrypted)
            a._file_path.set(str(source)+".enc")
            a._file_decrypt()
            self.wait_job()
            self.assertEqual(Path(str(source)+".enc.dec").read_bytes(), source.read_bytes())

    def test_avalanche_job(self):
        self.app._run_ava()
        self.wait_job()
        self.assertIn("Avalanche complete", self.app._status_var.get())
