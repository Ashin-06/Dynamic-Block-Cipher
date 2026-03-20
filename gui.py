#!/usr/bin/env python3
"""
gui.py  ─  Dynamic Block Cipher GUI
Secure 4-branch Generalized Feistel Network with AES S-Box, CBC, PBKDF2, HMAC-SHA256.

Run:  python gui.py
Requires: Python 3.8+  (tkinter is bundled with standard Python — no pip install needed)
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import threading
import os
import time

try:
    from cipher import FeistelCipher, derive_keys, derive_subkeys, \
                       round_function, xor_bytes
except ImportError:
    import sys
    print("ERROR: cipher.py not found. Place gui.py in the same folder as cipher.py.")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
#  COLOUR PALETTE  (dark-mode)
# ─────────────────────────────────────────────────────────────────────────────
BG       = "#0f0f1a"
BG2      = "#16162a"
BG3      = "#1e1e35"
ACCENT   = "#7c5cbf"
ACCENT2  = "#a87fd4"
GREEN    = "#4ec98e"
RED      = "#e05c6e"
YELLOW   = "#f0c060"
FG       = "#e0e0f0"
FG2      = "#9090b8"
FONT     = ("Segoe UI", 10)
FONT_B   = ("Segoe UI", 10, "bold")
FONT_BIG = ("Segoe UI", 13, "bold")
MONO     = ("Consolas", 9)


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def hamming(b1: bytes, b2: bytes) -> int:
    return sum(bin(a ^ b).count('1') for a, b in zip(b1, b2))


def get_round_states(block: bytes, subkeys: list) -> list:
    """Run the GFN forward and capture intermediate state after each round."""
    X = [block[i * 128:(i + 1) * 128] for i in range(4)]
    states = [b"".join(X)]
    for r in range(32):
        k0, k1 = subkeys[2 * r], subkeys[2 * r + 1]
        f0 = round_function(X[1], k0)
        f1 = round_function(X[3], k1)
        y0 = xor_bytes(X[0], f0)
        y2 = xor_bytes(X[2], f1)
        X = [X[1], y2, X[3], y0]
        states.append(b"".join(X))
    return states


# ─────────────────────────────────────────────────────────────────────────────
#  APPLICATION
# ─────────────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Dynamic Block Cipher  ─  Secure GFN v2")
        self.geometry("940x700")
        self.minsize(820, 580)
        self.configure(bg=BG)
        self._apply_style()
        self._build_ui()

    # ── ttk style ─────────────────────────────────────────────────────────────
    def _apply_style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")

        # base
        s.configure(".",             background=BG,  foreground=FG,  font=FONT)
        s.configure("TFrame",        background=BG)
        s.configure("TLabel",        background=BG,  foreground=FG,  font=FONT)

        # notebook
        s.configure("TNotebook",     background=BG2, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG3, foreground=FG2,
                    padding=[16, 7], font=FONT_B)
        s.map("TNotebook.Tab",
              background=[("selected", ACCENT)],
              foreground=[("selected", "#ffffff")])

        # buttons
        for name, bg, fg in [
            ("TButton",       ACCENT,  "#ffffff"),
            ("Green.TButton", GREEN,   "#000000"),
            ("Red.TButton",   RED,     "#ffffff"),
        ]:
            s.configure(name, background=bg, foreground=fg,
                        font=FONT_B, padding=[11, 5], relief="flat")
        s.map("TButton",       background=[("active", ACCENT2), ("pressed", "#5a3fa0")])
        s.map("Green.TButton", background=[("active", "#38b07a")])
        s.map("Red.TButton",   background=[("active", "#b83048")])

        # entry / progress / labelframe
        s.configure("TEntry",        fieldbackground=BG3, foreground=FG,
                    insertcolor=FG, font=MONO)
        s.configure("TScrollbar",    background=BG3, troughcolor=BG2,
                    arrowcolor=ACCENT)
        s.configure("TProgressbar",  troughcolor=BG3, background=ACCENT)
        s.configure("TLabelframe",   background=BG,  foreground=ACCENT2,
                    font=FONT_B, relief="groove", borderwidth=1)
        s.configure("TLabelframe.Label", background=BG, foreground=ACCENT2)

    # ── root layout ──────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        # header bar
        hdr = tk.Frame(self, bg=BG2, height=54)
        hdr.pack(fill="x")
        tk.Label(hdr, text="🔒  Dynamic Block Cipher  ─  Secure GFN v2",
                 bg=BG2, fg=ACCENT2,
                 font=("Segoe UI", 14, "bold")).pack(side="left", padx=22, pady=12)
        tk.Label(hdr,
                 text="AES S-Box  ·  CBC Mode  ·  PBKDF2  ·  HMAC-SHA256",
                 bg=BG2, fg=FG2, font=("Segoe UI", 9)).pack(side="right", padx=22)

        # notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=14, pady=(8, 4))

        self.tab_text = ttk.Frame(nb)
        self.tab_file = ttk.Frame(nb)
        self.tab_ava  = ttk.Frame(nb)

        nb.add(self.tab_text, text="  Text Cipher  ")
        nb.add(self.tab_file, text="  File Cipher  ")
        nb.add(self.tab_ava,  text="  Avalanche Effect  ")

        self._build_text_tab()
        self._build_file_tab()
        self._build_ava_tab()

        # status bar
        self._status_var = tk.StringVar(value="Ready")
        sb = tk.Frame(self, bg=BG2, height=28)
        sb.pack(fill="x")
        self._status_lbl = tk.Label(
            sb, textvariable=self._status_var,
            bg=BG2, fg=FG2, font=("Segoe UI", 9), anchor="w")
        self._status_lbl.pack(side="left", padx=14, pady=4)

    def _set_status(self, msg: str, color: str = FG2) -> None:
        self._status_var.set(msg)
        self._status_lbl.config(fg=color)

    # ── shared: password row ─────────────────────────────────────────────────
    def _make_pw_row(self, parent, row: int = 0) -> tk.StringVar:
        tk.Label(parent, text="Password:", bg=BG, fg=FG,
                 font=FONT_B).grid(row=row, column=0, sticky="w", padx=8, pady=6)
        var = tk.StringVar()
        entry = tk.Entry(parent, textvariable=var, show="●", width=36,
                         bg=BG3, fg=FG, insertbackground=FG,
                         font=MONO, relief="flat", bd=5)
        entry.grid(row=row, column=1, sticky="ew", padx=8, pady=6)
        eye = tk.BooleanVar(value=False)
        def _toggle():
            entry.config(show="" if eye.get() else "●")
        tk.Checkbutton(parent, text="👁", variable=eye, command=_toggle,
                       bg=BG, fg=FG2, selectcolor=BG3,
                       activebackground=BG, font=("Segoe UI", 11),
                       bd=0, cursor="hand2").grid(row=row, column=2, padx=4)
        return var

    # ── shared: scrolled text ────────────────────────────────────────────────
    def _make_text_box(self, parent, fg=FG, state="normal", **kw):
        t = scrolledtext.ScrolledText(
            parent, bg=BG3, fg=fg, insertbackground=FG,
            font=MONO, relief="flat", bd=5, wrap="word",
            state=state, **kw)
        return t

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB 1 — TEXT CIPHER
    # ─────────────────────────────────────────────────────────────────────────
    def _build_text_tab(self) -> None:
        p = self.tab_text

        # controls
        ctrl = tk.Frame(p, bg=BG)
        ctrl.pack(fill="x", padx=12, pady=(12, 4))
        ctrl.columnconfigure(1, weight=1)

        self._txt_pw = self._make_pw_row(ctrl, row=0)

        btn_row = tk.Frame(ctrl, bg=BG)
        btn_row.grid(row=0, column=3, padx=12)
        ttk.Button(btn_row, text="🔐  Encrypt",
                   command=self._text_encrypt).pack(side="left", padx=4)
        ttk.Button(btn_row, text="🔓  Decrypt", style="Green.TButton",
                   command=self._text_decrypt).pack(side="left", padx=4)
        ttk.Button(btn_row, text="✕  Clear",   style="Red.TButton",
                   command=self._text_clear).pack(side="left", padx=4)

        # panes
        panes = tk.Frame(p, bg=BG)
        panes.pack(fill="both", expand=True, padx=12, pady=4)
        panes.columnconfigure(0, weight=1)
        panes.columnconfigure(1, weight=1)
        panes.rowconfigure(1, weight=1)

        # --- input ---
        tk.Label(panes, text="INPUT — plaintext  or  hex ciphertext",
                 bg=BG, fg=FG2, font=FONT_B).grid(
                 row=0, column=0, sticky="w", padx=4, pady=(0, 2))
        self._txt_in = self._make_text_box(panes, height=14)
        self._txt_in.grid(row=1, column=0, sticky="nsew", padx=(4, 6), pady=4)

        # --- output ---
        hdr_out = tk.Frame(panes, bg=BG)
        hdr_out.grid(row=0, column=1, sticky="ew", padx=4, pady=(0, 2))
        tk.Label(hdr_out, text="OUTPUT",
                 bg=BG, fg=FG2, font=FONT_B).pack(side="left")
        ttk.Button(hdr_out, text="📋 Copy",
                   command=lambda: self._clipboard(
                       self._txt_out.get("1.0", "end").strip())
                   ).pack(side="right")

        self._txt_out = self._make_text_box(panes, fg=GREEN, state="disabled", height=14)
        self._txt_out.grid(row=1, column=1, sticky="nsew", padx=(6, 4), pady=4)

        # info strip
        self._txt_info = tk.Label(p, text="", bg=BG, fg=FG2,
                                  font=("Segoe UI", 9))
        self._txt_info.pack(anchor="w", padx=16, pady=(0, 6))

    def _text_encrypt(self) -> None:
        pw  = self._txt_pw.get()
        src = self._txt_in.get("1.0", "end").strip()
        if not src:
            return self._set_status("Enter some text to encrypt.", YELLOW)
        try:
            c = FeistelCipher(pw)
        except ValueError as e:
            return self._set_status(str(e), RED)

        def _run():
            try:
                t0  = time.time()
                enc = c.encrypt(src.encode("utf-8"))
                dt  = time.time() - t0
                self._txt_out_write(enc.hex(), GREEN)
                self._txt_info.config(
                    text=f"  {len(src.encode()):,} B  →  {len(enc):,} B ciphertext  "
                          f"|  {dt:.3f} s  |  {len(enc) // 512} GFN block(s)")
                self._set_status("Encrypted successfully.", GREEN)
            except Exception as e:
                self._set_status(str(e), RED)

        threading.Thread(target=_run, daemon=True).start()
        self._set_status("Encrypting…", YELLOW)

    def _text_decrypt(self) -> None:
        pw  = self._txt_pw.get()
        src = self._txt_in.get("1.0", "end").strip().replace("\n", "").replace(" ", "")
        if not src:
            return self._set_status("Paste hex ciphertext to decrypt.", YELLOW)
        try:
            c = FeistelCipher(pw)
        except ValueError as e:
            return self._set_status(str(e), RED)

        def _run():
            try:
                t0  = time.time()
                raw = bytes.fromhex(src)
                dec = c.decrypt(raw)
                dt  = time.time() - t0
                self._txt_out_write(dec.decode("utf-8"), GREEN)
                self._txt_info.config(
                    text=f"  {len(raw):,} B  →  {len(dec):,} B plaintext  "
                          f"|  {dt:.3f} s  |  HMAC VERIFIED ✓")
                self._set_status("Decrypted and integrity verified.", GREEN)
            except ValueError as e:
                self._txt_out_write(f"ERROR: {e}", RED)
                self._set_status(str(e), RED)
            except Exception as e:
                self._set_status(f"Error: {e}", RED)

        threading.Thread(target=_run, daemon=True).start()
        self._set_status("Decrypting…", YELLOW)

    def _text_clear(self) -> None:
        self._txt_in.delete("1.0", "end")
        self._txt_out.config(state="normal")
        self._txt_out.delete("1.0", "end")
        self._txt_out.config(state="disabled")
        self._txt_info.config(text="")
        self._set_status("Cleared.", FG2)

    def _txt_out_write(self, text: str, color: str) -> None:
        self._txt_out.config(state="normal")
        self._txt_out.delete("1.0", "end")
        self._txt_out.insert("end", text)
        self._txt_out.config(state="disabled", fg=color)

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB 2 — FILE CIPHER
    # ─────────────────────────────────────────────────────────────────────────
    def _build_file_tab(self) -> None:
        p = self.tab_file

        ctrl = tk.Frame(p, bg=BG)
        ctrl.pack(fill="x", padx=16, pady=(14, 6))
        ctrl.columnconfigure(1, weight=1)

        self._file_pw = self._make_pw_row(ctrl, row=0)

        # file picker row
        tk.Label(ctrl, text="File:", bg=BG, fg=FG,
                 font=FONT_B).grid(row=1, column=0, sticky="w", padx=8, pady=6)
        self._file_path = tk.StringVar()
        tk.Entry(ctrl, textvariable=self._file_path, width=44,
                 bg=BG3, fg=FG, insertbackground=FG, font=MONO,
                 relief="flat", bd=5).grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Button(ctrl, text="Browse…",
                   command=self._browse).grid(row=1, column=2, padx=6)

        # action buttons
        btn_row = tk.Frame(p, bg=BG)
        btn_row.pack(pady=10)
        ttk.Button(btn_row, text="🔐  Encrypt File",
                   command=self._file_encrypt).pack(side="left", padx=8, ipadx=10)
        ttk.Button(btn_row, text="🔓  Decrypt File", style="Green.TButton",
                   command=self._file_decrypt).pack(side="left", padx=8, ipadx=10)

        # progress bar
        self._file_prog = ttk.Progressbar(p, mode="indeterminate", length=440)
        self._file_prog.pack(pady=4)

        # log
        tk.Label(p, text="Log:", bg=BG, fg=FG2,
                 font=FONT_B).pack(anchor="w", padx=16, pady=(6, 2))
        self._file_log = self._make_text_box(p, fg=FG2, state="disabled")
        self._file_log.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    def _browse(self) -> None:
        path = filedialog.askopenfilename(title="Select a file")
        if path:
            self._file_path.set(path)

    def _file_log_write(self, msg: str) -> None:
        self._file_log.config(state="normal")
        self._file_log.insert("end", msg + "\n")
        self._file_log.see("end")
        self._file_log.config(state="disabled")

    def _file_encrypt(self) -> None:
        pw   = self._file_pw.get()
        path = self._file_path.get().strip()
        if not path or not os.path.exists(path):
            return self._set_status("Select a valid file first.", YELLOW)
        try:
            c = FeistelCipher(pw)
        except ValueError as e:
            return self._set_status(str(e), RED)

        def _run():
            self._file_prog.start(10)
            try:
                t0 = time.time()
                with open(path, "rb") as f:
                    data = f.read()
                self._file_log_write(f"[READ]  {path}  ({len(data):,} bytes)")
                enc      = c.encrypt(data)
                out_path = path + ".enc"
                with open(out_path, "wb") as f:
                    f.write(enc)
                dt = time.time() - t0
                self._file_log_write(
                    f"[OK]    Encrypted  →  {out_path}  ({len(enc):,} bytes)  |  {dt:.3f}s")
                self._set_status(f"Encrypted → {os.path.basename(out_path)}", GREEN)
            except Exception as e:
                self._file_log_write(f"[ERROR] {e}")
                self._set_status(str(e), RED)
            finally:
                self._file_prog.stop()

        threading.Thread(target=_run, daemon=True).start()
        self._set_status("Encrypting file…", YELLOW)

    def _file_decrypt(self) -> None:
        pw   = self._file_pw.get()
        path = self._file_path.get().strip()
        if not path or not os.path.exists(path):
            return self._set_status("Select a valid .enc file first.", YELLOW)
        try:
            c = FeistelCipher(pw)
        except ValueError as e:
            return self._set_status(str(e), RED)

        def _run():
            self._file_prog.start(10)
            try:
                t0 = time.time()
                with open(path, "rb") as f:
                    data = f.read()
                self._file_log_write(f"[READ]  {path}  ({len(data):,} bytes)")
                dec      = c.decrypt(data)
                out_path = path[:-4] if path.endswith(".enc") else path + ".dec"
                with open(out_path, "wb") as f:
                    f.write(dec)
                dt = time.time() - t0
                self._file_log_write(
                    f"[OK]    Decrypted  →  {out_path}  ({len(dec):,} bytes)  "
                    f"|  {dt:.3f}s  |  HMAC VERIFIED ✓")
                self._set_status(f"Decrypted → {os.path.basename(out_path)}", GREEN)
            except ValueError as e:
                self._file_log_write(f"[FAIL]  {e}")
                self._set_status(str(e), RED)
            except Exception as e:
                self._file_log_write(f"[ERROR] {e}")
                self._set_status(str(e), RED)
            finally:
                self._file_prog.stop()

        threading.Thread(target=_run, daemon=True).start()
        self._set_status("Decrypting file…", YELLOW)

    # ─────────────────────────────────────────────────────────────────────────
    #  TAB 3 — AVALANCHE EFFECT
    # ─────────────────────────────────────────────────────────────────────────
    def _build_ava_tab(self) -> None:
        p = self.tab_ava

        tk.Label(p, text="Avalanche Effect — Bit Diffusion Over 32 Rounds",
                 bg=BG, fg=ACCENT2, font=FONT_BIG).pack(pady=(14, 2))
        tk.Label(p,
                 text="Flip 1 bit in the plaintext or key — a strong cipher diffuses it "
                      "to ~50 % (2048 / 4096) of all output bits by round 8–12.",
                 bg=BG, fg=FG2, font=FONT, wraplength=760).pack()

        ttk.Button(p, text="▶   Run Avalanche Test",
                   command=self._run_ava).pack(pady=10, ipadx=20)

        self._ava_prog = ttk.Progressbar(p, mode="indeterminate", length=380)
        self._ava_prog.pack()

        self._ava_canvas = tk.Canvas(p, bg=BG2, bd=0, highlightthickness=0)
        self._ava_canvas.pack(fill="both", expand=True, padx=16, pady=12)

    def _run_ava(self) -> None:
        def _run():
            self._ava_prog.start(8)
            self._ava_canvas.delete("all")
            try:
                pw   = "AvalancheDemo2025"
                salt = os.urandom(16)
                k_enc, _ = derive_keys(pw, salt)
                subkeys  = derive_subkeys(k_enc)

                blk    = os.urandom(512)
                mut_pt = bytes([blk[0] ^ 0x01]) + blk[1:]
                k_mut  = bytes([k_enc[0] ^ 0x01]) + k_enc[1:]
                sk_mut = derive_subkeys(k_mut)

                s_orig = get_round_states(blk,    subkeys)
                s_pt   = get_round_states(mut_pt, subkeys)
                s_key  = get_round_states(blk,    sk_mut)

                pt_d  = [hamming(a, b) for a, b in zip(s_orig, s_pt)]
                key_d = [hamming(a, b) for a, b in zip(s_orig, s_key)]

                self.after(0, lambda: self._draw_ava(pt_d, key_d))
            finally:
                self._ava_prog.stop()

        threading.Thread(target=_run, daemon=True).start()

    def _draw_ava(self, pt_d: list, key_d: list) -> None:
        c  = self._ava_canvas
        c.delete("all")
        W  = c.winfo_width()
        H  = c.winfo_height()
        if W < 200 or H < 200:
            W, H = 880, 340

        PL, PR, PT, PB = 68, 24, 28, 54
        gw = W - PL - PR
        gh = H - PT - PB
        MAX = 4096

        def rx(r): return PL + r * gw / 32
        def ry(v): return PT + gh - v * gh / MAX

        # grid lines
        for v in range(0, MAX + 1, 1024):
            y = ry(v)
            c.create_line(PL, y, W - PR, y, fill="#24244a", dash=(5, 4))
            c.create_text(PL - 8, y, text=str(v),
                          anchor="e", fill=FG2, font=("Consolas", 8))
        for r in range(0, 33, 4):
            x = rx(r)
            c.create_line(x, PT, x, H - PB, fill="#24244a", dash=(5, 4))
            c.create_text(x, H - PB + 14, text=str(r),
                          fill=FG2, font=("Consolas", 8))

        # ideal 50 % line
        yi = ry(2048)
        c.create_line(PL, yi, W - PR, yi, fill=YELLOW, dash=(10, 5), width=1.5)
        c.create_text(W - PR + 4, yi, text="Ideal 50%",
                      anchor="w", fill=YELLOW, font=("Segoe UI", 8))

        # series
        for diffs, color in [(key_d, RED), (pt_d, ACCENT)]:
            coords = []
            for r, v in enumerate(diffs):
                coords += [rx(r), ry(v)]
            c.create_line(*coords, fill=color, width=2.5, smooth=True)
            for r, v in enumerate(diffs):
                x, y = rx(r), ry(v)
                c.create_oval(x - 3, y - 3, x + 3, y + 3, fill=color, outline="")

        # legend
        for i, (color, label) in enumerate([
            (RED,    f"1-bit Key Change      → {key_d[-1]} bits  ({key_d[-1]/MAX*100:.1f}%)  after round 32"),
            (ACCENT, f"1-bit Plaintext Change → {pt_d[-1]} bits  ({pt_d[-1]/MAX*100:.1f}%)  after round 32"),
            (YELLOW, "Ideal avalanche = 2048 bits (50%)"),
        ]):
            lx = PL + 10
            ly = PT + 10 + i * 20
            c.create_rectangle(lx, ly, lx + 16, ly + 12, fill=color, outline="")
            c.create_text(lx + 22, ly + 6, text=label, anchor="w",
                          fill=FG, font=("Segoe UI", 9))

        # axis labels
        c.create_text(W // 2, H - 8,  text="Feistel Round",
                      fill=FG2, font=("Segoe UI", 9))
        c.create_text(14, H // 2, text="Hamming\nDistance\n(bits)",
                      fill=FG2, font=("Segoe UI", 8), angle=90)

        self._set_status(
            f"Avalanche complete — Plaintext diff: {pt_d[-1]} bits "
            f"({pt_d[-1]/MAX*100:.1f}%)  |  Key diff: {key_d[-1]} bits "
            f"({key_d[-1]/MAX*100:.1f}%)", GREEN)

    # ─────────────────────────────────────────────────────────────────────────────
    #  UTILITIES
    # ─────────────────────────────────────────────────────────────────────────────
    def _clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Copied to clipboard.", GREEN)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
