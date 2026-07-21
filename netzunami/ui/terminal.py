import threading
import queue
import time
import re
import tkinter as tk
from tkinter import font as tkfont

from ..connector import ssh_connect, run_commands, detect_vendor, fetch_device_info
from ..analyzer import COMMON_ISSUES


ANSI_COLORS = {
    "30": "#000000",  # black
    "31": "#cc0000",  # red
    "32": "#4e9a06",  # green
    "33": "#c4a000",  # yellow
    "34": "#3465a4",  # blue
    "35": "#75507b",  # magenta
    "36": "#06989a",  # cyan
    "37": "#d3d7cf",  # white
    "90": "#555753",  # bright black
    "91": "#ef2929",  # bright red
    "92": "#8ae234",  # bright green
    "93": "#fce94f",  # bright yellow
    "94": "#729fcf",  # bright blue
    "95": "#ad7fa8",  # bright magenta
    "96": "#34e2e2",  # bright cyan
    "97": "#eeeeec",  # bright white
}

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m|\x1b\[K|\x1b\[\d+[ABCD]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


class TerminalWidget(tk.Frame):
    def __init__(self, parent, vault=None, on_finding=None, on_device_info=None, **kw):
        super().__init__(parent, **kw)
        self.vault = vault
        self.on_finding = on_finding
        self.on_device_info = on_device_info
        self.rules = COMMON_ISSUES.get("cisco", [])
        self.vendor = "cisco"

        self.input_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.ssh_client = None
        self.channel = None
        self.connected = False
        self.buffer = ""

        self.bg = "#0a0a0a"
        self.fg = "#d3d7cf"

        self._build_ui()

    def _build_ui(self):
        self.text = tk.Text(
            self,
            bg=self.bg,
            fg=self.fg,
            insertbackground="#00ff00",
            font=("Consolas", 11),
            wrap=tk.WORD,
            state=tk.DISABLED,
            padx=6,
            pady=4,
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=0,
        )
        self.text.pack(fill=tk.BOTH, expand=True)

        self.text.tag_config("prompt", foreground="#00ff00")
        self.text.tag_config("error", foreground="#ff4444")
        self.text.tag_config("warning", foreground="#ffaa00")
        self.text.tag_config("info", foreground="#888888")
        self.text.tag_config("input", foreground="#ffffff")

        self.text.bind("<Key>", self._on_key)
        self.text.bind("<Return>", self._on_enter)

        self._input_mode = False

    def _write(self, text: str, tag: str | None = None):
        self.text.config(state=tk.NORMAL)
        if tag:
            self.text.insert(tk.END, text, tag)
        else:
            self._write_colored(text)
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)

    def _write_colored(self, text: str):
        parts = ANSI_RE.split(text)
        color = self.fg
        for part in parts:
            if not part:
                continue
            if part in ANSI_COLORS:
                color = ANSI_COLORS[part]
                continue
            self.text.insert(tk.END, part, ("ansi",))
            self.text.tag_config("ansi", foreground=color)

    def connect(self, host: str, user: str, password: str = "",
                key_path: str = "", enable_pw: str = ""):
        self.host = host
        self.user = user
        self.password = password
        self.key_path = key_path
        self.enable_pw = enable_pw

        self._write(f"Connecting to {host}...\n", "info")
        threading.Thread(target=self._ssh_thread, daemon=True).start()

    def _ssh_thread(self):
        try:
            self.ssh_client = ssh_connect(
                host=self.host,
                user=self.user,
                password=self.password or None,
                key_path=self.key_path or None,
            )
            self.channel = self.ssh_client.invoke_shell()
            self.channel.settimeout(1)
            self.connected = True
            self.after(0, lambda: self._write(f"Connected to {self.host}\n", "prompt"))

            self.vendor = detect_vendor(self.channel)
            self.rules = COMMON_ISSUES.get(self.vendor, COMMON_ISSUES.get("cisco", []))
            self.after(0, lambda: self._write(f"Vendor: {self.vendor}\n", "info"))

            if self.enable_pw:
                self.channel.send("enable\n")
                time.sleep(0.3)
                self.channel.send(f"{self.enable_pw}\n")
                time.sleep(0.5)
            self.channel.send("terminal length 0\n")
            time.sleep(0.5)

            threading.Thread(target=self._read_thread, daemon=True).start()
            threading.Thread(target=self._write_thread, daemon=True).start()
            threading.Thread(target=self._fetch_info_thread, daemon=True).start()
        except Exception as e:
            self.after(0, lambda: self._write(f"Error: {e}\n", "error"))

    def _fetch_info_thread(self):
        try:
            info = fetch_device_info(self.ssh_client, self.host, self.enable_pw or None)
            if self.on_device_info:
                self.after(0, lambda: self.on_device_info(info))
        except Exception:
            pass

    def _read_thread(self):
        while self.connected:
            try:
                data = self.channel.recv(65535).decode("utf-8", errors="replace")
                if data:
                    self.output_queue.put(data)
                    self._check_findings(data)
            except:
                if self.connected:
                    time.sleep(0.05)

    def _write_thread(self):
        while self.connected:
            try:
                data = self.output_queue.get(timeout=0.1)
            except:
                continue
            self.after(0, lambda d=data: self._write(d))

    def _check_findings(self, text: str):
        for line in text.splitlines():
            stripped = line.strip()
            for rule in self.rules:
                if re.search(rule["pattern"], stripped, re.IGNORECASE):
                    if self.on_finding:
                        self.after(
                            0,
                            lambda r=rule, s=stripped: self.on_finding(r, s),
                        )

    def _on_key(self, event):
        if not self.connected:
            return
        if event.char and event.char.isprintable():
            self.channel.send(event.char)
            return "break"
        if event.keysym == "BackSpace":
            self.channel.send("\x7f")
            return "break"
        if event.keysym == "Tab":
            self.channel.send("\t")
            return "break"
        if event.keysym in ("Left", "Right", "Up", "Down"):
            dirs = {"Up": "\x1b[A", "Down": "\x1b[B", "Right": "\x1b[C", "Left": "\x1b[D"}
            self.channel.send(dirs[event.keysym])
            return "break"

    def _on_enter(self, event):
        if self.connected:
            self.channel.send("\n")
        return "break"

    def send_command(self, cmd: str):
        if self.connected and self.channel:
            self.channel.send(cmd + "\n")

    def disconnect(self):
        self.connected = False
        if self.channel:
            try:
                self.channel.close()
            except:
                pass
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass

    def get_buffer(self) -> str:
        return self.text.get("1.0", tk.END)
