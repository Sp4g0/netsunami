import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import os
import sys
import threading
from pathlib import Path

from .terminal import TerminalWidget
from .findings import FindingsPanel
from .vault import Vault
from .sessions import load_sessions, save_sessions, add_session, remove_session, save_last_session, load_last_session


DEFAULT_FONT = ("Segoe UI", 10)
MONO_FONT = ("Consolas", 11)


class NetzunamiApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Netzunami — Network Terminal")
        self.root.geometry("1280x800")
        self.root.minsize(900, 600)

        self._setup_styles()
        self._setup_menubar()
        self._build_ui()

        self.vault = Vault()
        self.current_terminal = None

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._unlock_vault()

    def _setup_styles(self):
        self.root.configure(bg="#1a1a1a")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#1a1a1a")
        style.configure("TLabel", background="#1a1a1a", foreground="#d3d7cf", font=DEFAULT_FONT)
        style.configure("TButton", background="#333333", foreground="#d3d7cf", font=DEFAULT_FONT, borderwidth=0)
        style.map("TButton", background=[("active", "#444444")])
        style.configure("Treeview", background="#2a2a2a", foreground="#d3d7cf", fieldbackground="#2a2a2a")
        style.map("Treeview", background=[("selected", "#444444")])

    def _setup_menubar(self):
        menubar = tk.Menu(self.root, bg="#2a2a2a", fg="#d3d7cf", activebackground="#444444", activeforeground="white")

        file_menu = tk.Menu(menubar, tearoff=0, bg="#2a2a2a", fg="#d3d7cf", activebackground="#444444")
        file_menu.add_command(label="Nuova connessione", command=self._new_connection, accelerator="Ctrl+N")
        file_menu.add_command(label="Quick Connect...", command=self._quick_connect, accelerator="Ctrl+Q")
        file_menu.add_separator()
        file_menu.add_command(label="Importa sessione CRT...", command=self._import_crt)
        file_menu.add_separator()
        file_menu.add_command(label="Esci", command=self._on_close, accelerator="Ctrl+Q")
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=0, bg="#2a2a2a", fg="#d3d7cf", activebackground="#444444")
        edit_menu.add_command(label="Vault password...", command=self._manage_vault)
        edit_menu.add_command(label="Preferenze...", command=self._preferences)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        tools_menu = tk.Menu(menubar, tearoff=0, bg="#2a2a2a", fg="#d3d7cf", activebackground="#444444")
        tools_menu.add_command(label="Analizza config...", command=self._analyze_config)
        tools_menu.add_command(label="Esegui comando bulk...", command=self._bulk_command)
        tools_menu.add_separator()
        tools_menu.add_command(label="Backup massivo...", command=self._bulk_backup)
        tools_menu.add_command(label="Push template massivo...", command=self._bulk_push)
        tools_menu.add_separator()
        tools_menu.add_command(label="Avvia listener sessioni", command=self._start_listener)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg="#2a2a2a", fg="#d3d7cf", activebackground="#444444")
        help_menu.add_command(label="About", command=self._show_about)
        help_menu.add_command(label="Shortcuts", command=self._show_shortcuts)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

        self.root.bind("<Control-n>", lambda e: self._new_connection())
        self.root.bind("<Control-q>", lambda e: self._quick_connect())
        self.root.bind("<Control-t>", lambda e: self._new_tab())
        self.root.bind("<Control-w>", lambda e: self._close_tab())

    def _build_ui(self):
        self.panes = tk.PanedWindow(
            self.root,
            orient=tk.HORIZONTAL,
            bg="#1a1a1a",
            sashwidth=3,
            sashrelief=tk.FLAT,
        )
        self.panes.pack(fill=tk.BOTH, expand=True)

        left_frame = tk.Frame(self.panes, bg="#1a1a1a", width=220)
        self._build_session_panel(left_frame)
        self.panes.add(left_frame, minsize=180, width=220)

        center_frame = tk.Frame(self.panes, bg="#0a0a0a")
        self._build_terminal_panel(center_frame)
        self.panes.add(center_frame, minsize=500)

        right_frame = tk.Frame(self.panes, bg="#1a1a1a", width=300)
        self._build_findings_panel(right_frame)
        self.panes.add(right_frame, minsize=200, width=300)

        self._build_statusbar()

    def _build_session_panel(self, parent):
        header = tk.Label(
            parent,
            text=" Sessioni",
            font=("Segoe UI", 10, "bold"),
            bg="#1a1a1a",
            fg="#d3d7cf",
            anchor="w",
            padx=8,
            pady=6,
        )
        header.pack(fill=tk.X)

        btn_frame = tk.Frame(parent, bg="#1a1a1a")
        btn_frame.pack(fill=tk.X, padx=6, pady=2)

        tk.Button(
            btn_frame, text="+", bg="#2d5a27", fg="white",
            relief=tk.FLAT, padx=8, font=("Segoe UI", 10, "bold"),
            command=self._new_connection,
        ).pack(side=tk.LEFT, padx=1)

        tk.Button(
            btn_frame, text="⚡", bg="#5a3a27", fg="white",
            relief=tk.FLAT, padx=8, font=("Segoe UI", 10, "bold"),
            command=self._quick_connect,
        ).pack(side=tk.LEFT, padx=1)

        tk.Button(
            btn_frame, text="✕", bg="#5a2a2a", fg="white",
            relief=tk.FLAT, padx=8, font=("Segoe UI", 10, "bold"),
            command=self._delete_session,
        ).pack(side=tk.LEFT, padx=1)

        self.session_list = tk.Listbox(
            parent,
            bg="#2a2a2a",
            fg="#d3d7cf",
            selectbackground="#444444",
            font=MONO_FONT,
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=0,
        )
        self.session_list.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        self.session_list.bind("<Double-Button-1>", lambda e: self._connect_selected())

        self._refresh_session_list()

    def _build_terminal_panel(self, parent):
        self.tab_frame = tk.Frame(parent, bg="#1a1a1a", height=28)
        self.tab_frame.pack(fill=tk.X)

        self.tabs = ttk.Notebook(parent)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        welcome = tk.Frame(self.tabs, bg="#0a0a0a")
        tk.Label(
            welcome,
            text="Netzunami v0.1\n\nCtrl+N: Nuova connessione\nCtrl+Q: Quick Connect\n\nSeleziona una sessione a sinistra\nper connetterti a un apparato.",
            bg="#0a0a0a",
            fg="#888888",
            font=("Segoe UI", 12),
            justify=tk.CENTER,
        ).pack(expand=True)
        self.tabs.add(welcome, text="  Benvenuto  ")

    def _build_findings_panel(self, parent):
        self.findings_panel = FindingsPanel(parent, bg="#1a1a1a")
        self.findings_panel.pack(fill=tk.BOTH, expand=True)

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg="#1e1e1e", height=26)
        bar.pack(fill=tk.X)

        SEG_BG = "#1e1e1e"
        SEG_FG = "#aaaaaa"
        SEP_COLOR = "#333333"
        FONT = ("Consolas", 9)

        def seg(text="", width=0):
            lbl = tk.Label(bar, text=text, bg=SEG_BG, fg=SEG_FG,
                          font=FONT, anchor="w", padx=6)
            if width:
                lbl.config(width=width)
            return lbl

        def sep():
            s = tk.Label(bar, text="│", bg=SEG_BG, fg=SEP_COLOR,
                        font=FONT, padx=3)
            return s

        self.bar_host = seg(" Disconnesso")
        self.bar_host.pack(side=tk.LEFT)

        self.bar_model = seg()
        self.bar_ver = seg()
        self.bar_uptime = seg()
        self.bar_cpu = seg()
        self.bar_mem = seg()

        self.bar_segments = [
            self.bar_model, self.bar_ver,
            self.bar_uptime, self.bar_cpu, self.bar_mem,
        ]

        for s in self.bar_segments:
            s.pack(side=tk.LEFT)
            if s is not self.bar_segments[-1]:
                sep().pack(side=tk.LEFT)

        self.bar_status = seg("0 findings", width=12)
        self.bar_status.pack(side=tk.RIGHT)

        self.bar_vault = seg("Vault: chiuso", width=12)
        self.bar_vault.pack(side=tk.RIGHT)
        sep().pack(side=tk.RIGHT)

    def _update_statusbar(self, host="", info=None, finding_count=0, vault_ok=False):
        if not host:
            self.bar_host.config(text=" Disconnesso")
            for s in self.bar_segments:
                s.config(text="")
            self.bar_status.config(text="0 findings")
            self.bar_vault.config(text="Vault: chiuso")
            return

        self.bar_host.config(text=f" {host}")
        if info:
            parts = [
                info.model or "",
                info.ios_version or "",
                info.uptime or "",
                f"CPU: {info.cpu}" if info.cpu else "",
                info.memory or "",
            ]
            for lbl, val in zip(self.bar_segments, parts):
                lbl.config(text=val)

        self.bar_status.config(text=f"{finding_count} findings")
        self.bar_vault.config(text="Vault: ✓" if vault_ok else "Vault: chiuso")

    def _unlock_vault(self):
        vault_path = Path.home() / ".netzunami" / "vault.enc"
        if vault_path.exists():
            pw = simpledialog.askstring(
                "Vault Netzunami",
                "Inserisci master password del vault:",
                show="*",
                parent=self.root,
            )
            if pw:
                self.vault.unlock(pw)
                self._update_status()
        else:
            pw = simpledialog.askstring(
                "Crea Vault",
                "Crea una master password per il vault (password crittografate):",
                show="*",
                parent=self.root,
            )
            if pw:
                self.vault.unlock(pw)
                self.vault.save()
                self._update_status()

    def _new_connection(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Nuova connessione")
        dialog.geometry("450x350")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)
        dialog.grab_set()

        last = load_last_session()
        fields = {}
        row = 0

        for label, key, default in [
            ("Nome sessione:", "name", ""),
            ("Host/IP:", "host", ""),
            ("Username:", "user", last.get("user", "admin")),
            ("Porta:", "port", str(last.get("port", 22))),
            ("Password:", "password", ""),
            ("Enable password:", "enable_pw", ""),
        ]:
            tk.Label(dialog, text=label, bg="#1a1a1a", fg="#d3d7cf", anchor="w").grid(
                row=row, column=0, sticky="w", padx=10, pady=4
            )
            show_char = "*" if key in ("password", "enable_pw") else None
            entry = tk.Entry(dialog, bg="#333333", fg="white", insertbackground="white",
                            relief=tk.FLAT, width=35, show=show_char or "")
            entry.grid(row=row, column=1, padx=10, pady=4)
            if default:
                entry.insert(0, default)
            fields[key] = entry
            row += 1

        def do_connect():
            vals = {k: w.get() for k, w in fields.items()}
            if not vals["host"]:
                return
            add_session(vals["name"] or vals["host"], vals["host"],
                       vals["user"] or "admin", int(vals["port"] or 22))
            if vals["password"]:
                self.vault.set(vals["host"], vals["user"] or "admin", vals["password"])
            if vals["enable_pw"]:
                self.vault.set(vals["host"], "enable", vals["enable_pw"])
            save_last_session(vals["user"] or "admin", int(vals["port"] or 22))
            dialog.destroy()
            self._open_terminal(vals["host"], vals["user"] or "admin", vals["password"],
                              enable_pw=vals["enable_pw"])

        btn = tk.Button(dialog, text="Connetti", bg="#2d5a27", fg="white",
                       relief=tk.FLAT, padx=20, pady=6, command=do_connect)
        btn.grid(row=row, column=0, columnspan=2, pady=20)

    def _quick_connect(self):
        host = simpledialog.askstring("Quick Connect", "Host/IP:", parent=self.root)
        if host:
            user = simpledialog.askstring("Quick Connect", "Username:", parent=self.root, initialvalue="admin")
            user = user or "admin"
            pw = self.vault.get(host, user) or ""
            enable_pw = self.vault.get(host, "enable") or ""
            self._open_terminal(host, user, pw, enable_pw=enable_pw)

    def _connect_selected(self):
        sel = self.session_list.curselection()
        if not sel:
            return
        idx = sel[0]
        sessions = load_sessions()
        if idx >= len(sessions):
            return
        s = sessions[idx]
        pw = self.vault.get(s["host"], s["user"]) or ""
        enable_pw = self.vault.get(s["host"], "enable") or ""
        self._open_terminal(s["host"], s["user"], pw, enable_pw=enable_pw)

    def _open_terminal(self, host: str, user: str, password: str = "", enable_pw: str = ""):
        tab = tk.Frame(self.tabs, bg="#0a0a0a")
        terminal = TerminalWidget(tab, vault=self.vault,
                                 on_finding=self._on_finding,
                                 on_device_info=self._on_device_info)
        terminal.pack(fill=tk.BOTH, expand=True)

        if password:
            self.tabs.add(tab, text=f"  {host}  ")
            self.tabs.select(tab)
            self.current_terminal = terminal
            terminal.connect(host, user, password, enable_pw=enable_pw)
            self._update_statusbar(host, finding_count=0, vault_ok=bool(self.vault._key))
        else:
            pw_dialog = tk.Toplevel(self.root)
            pw_dialog.title(f"Password per {user}@{host}")
            pw_dialog.geometry("350x240")
            pw_dialog.configure(bg="#1a1a1a")
            pw_dialog.transient(self.root)
            pw_dialog.grab_set()

            tk.Label(pw_dialog, text=f"Password SSH per {user}@{host}:",
                    bg="#1a1a1a", fg="#d3d7cf").pack(pady=8)
            pw_entry = tk.Entry(pw_dialog, show="*", bg="#333333", fg="white",
                               insertbackground="white", relief=tk.FLAT, width=30)
            pw_entry.pack(pady=3)

            tk.Label(pw_dialog, text="Enable password (opzionale):",
                    bg="#1a1a1a", fg="#d3d7cf").pack(pady=8)
            en_entry = tk.Entry(pw_dialog, show="*", bg="#333333", fg="white",
                               insertbackground="white", relief=tk.FLAT, width=30)
            en_entry.pack(pady=3)
            save_var = tk.BooleanVar()
            tk.Checkbutton(
                pw_dialog, text="Salva nel vault", variable=save_var,
                bg="#1a1a1a", fg="#d3d7cf", selectcolor="#333333",
                activebackground="#1a1a1a", activeforeground="#d3d7cf",
            ).pack(pady=5)

            def do_connect():
                pw = pw_entry.get()
                en = en_entry.get()
                if save_var.get():
                    if pw:
                        self.vault.set(host, user, pw)
                    if en:
                        self.vault.set(host, "enable", en)
                pw_dialog.destroy()
                self.tabs.add(tab, text=f"  {host}  ")
                self.tabs.select(tab)
                self.current_terminal = terminal
                terminal.connect(host, user, pw, enable_pw=en)
                self._update_statusbar(host, finding_count=0, vault_ok=bool(self.vault._key))

            tk.Button(pw_dialog, text="Connetti", bg="#2d5a27", fg="white",
                     relief=tk.FLAT, padx=20, command=do_connect).pack(pady=10)

    def _on_device_info(self, info):
        self._update_statusbar(host=getattr(self.current_terminal, 'host', ''),
                              info=info,
                              finding_count=self.findings_panel.listbox.size(),
                              vault_ok=bool(self.vault._key))

    def _on_finding(self, rule: dict, line: str):
        self.findings_panel.add_finding(rule, line)
        n = self.findings_panel.listbox.size()
        self._update_statusbar(host=getattr(self.current_terminal, 'host', ''),
                              finding_count=n,
                              vault_ok=bool(self.vault._key))

    def _new_tab(self):
        self._quick_connect()

    def _close_tab(self):
        current = self.tabs.select()
        if current:
            self.tabs.forget(current)
        n_tabs = len([c for c in self.tabs.children if c != "custom"])
        if n_tabs <= 1:
            self._update_statusbar()

    def _refresh_session_list(self):
        self.session_list.delete(0, tk.END)
        for s in load_sessions():
            self.session_list.insert(tk.END, f"{s.get('name', s['host']):<20} {s['host']}")

    def _delete_session(self):
        sel = self.session_list.curselection()
        if not sel:
            return
        idx = sel[0]
        sessions = load_sessions()
        if idx >= len(sessions):
            return
        host = sessions[idx]["host"]
        if messagebox.askyesno("Elimina", f"Eliminare la sessione {host}?"):
            remove_session(host)
            self._refresh_session_list()

    def _import_crt(self):
        import tkinter.filedialog as fd
        filepath = fd.askopenfilename(
            title="Importa sessione CRT/SecureCRT",
            filetypes=[("CRT Session", "*.ini"), ("All files", "*.*")],
            parent=self.root,
        )
        if not filepath:
            return
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(filepath)
            if "SSH2" in config:
                host = config["SSH2"].get("Hostname", "")
                user = config["SSH2"].get("Username", "admin")
                port = config["SSH2"].get("Port", "22")
                name = Path(filepath).stem
                add_session(name, host, user, int(port))
                self._refresh_session_list()
                messagebox.showinfo("Importato", f"Sessione {name} importata.")
        except Exception as e:
            messagebox.showerror("Errore", f"Impossibile importare: {e}")

    def _manage_vault(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Vault Password")
        dialog.geometry("500x350")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)

        tk.Label(dialog, text="Password salvate:", bg="#1a1a1a", fg="#d3d7cf",
                font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=6)

        lb = tk.Listbox(dialog, bg="#2a2a2a", fg="#d3d7cf", selectbackground="#444444")
        lb.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        for c in self.vault.list_sessions():
            lb.insert(tk.END, f"{c['user']}@{c['host']}")

        def delete_cred():
            sel = lb.curselection()
            if sel:
                creds = self.vault.list_sessions()
                if sel[0] < len(creds):
                    c = creds[sel[0]]
                    self.vault.delete(c["host"], c["user"])
                    lb.delete(sel[0])

        tk.Button(dialog, text="Elimina selezionata", bg="#5a2a2a", fg="white",
                 relief=tk.FLAT, command=delete_cred).pack(pady=6)

    def _analyze_config(self):
        import tkinter.filedialog as fd
        filepath = fd.askopenfilename(
            title="Seleziona running-config",
            filetypes=[("Config files", "*.cfg;*.txt"), ("All files", "*.*")],
            parent=self.root,
        )
        if filepath:
            from ..analyzer import analyze_with_rules
            from ..parser import parse_running_config

            with open(filepath) as f:
                raw = f.read()
            blocks = parse_running_config(raw)
            findings = analyze_with_rules(blocks)

            dialog = tk.Toplevel(self.root)
            dialog.title(f"Analisi: {Path(filepath).name}")
            dialog.geometry("700x500")
            dialog.configure(bg="#1a1a1a")
            dialog.transient(self.root)

            txt = tk.Text(
                dialog, bg="#0a0a0a", fg="#d3d7cf", font=MONO_FONT,
                relief=tk.FLAT, borderwidth=0, wrap=tk.WORD,
            )
            txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            for f in findings:
                sev = f.severity.value
                txt.insert(tk.END, f"[{sev}] {f.title}\n")
                txt.insert(tk.END, f"       {f.detail}\n")
                if f.suggestion:
                    txt.insert(tk.END, f"       → {f.suggestion}\n")
                txt.insert(tk.END, "-" * 50 + "\n")

            txt.config(state=tk.DISABLED)

    def _bulk_command(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Comando bulk")
        dialog.geometry("500x400")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)

        tk.Label(dialog, text="Comando da eseguire su tutte le sessioni:",
                bg="#1a1a1a", fg="#d3d7cf").pack(anchor="w", padx=10, pady=6)

        cmd_entry = tk.Entry(dialog, bg="#333333", fg="white",
                            insertbackground="white", relief=tk.FLAT, width=50)
        cmd_entry.pack(padx=10, pady=4, fill=tk.X)

        output = tk.Text(dialog, bg="#0a0a0a", fg="#d3d7cf", font=MONO_FONT,
                        relief=tk.FLAT, borderwidth=0)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        def run():
            cmd = cmd_entry.get()
            if not cmd:
                return
            output.insert(tk.END, f"Esecuzione: {cmd}\n{'='*40}\n")
            sessions = load_sessions()
            for s in sessions:
                output.insert(tk.END, f"\n--- {s['host']} ---\n")
                pw = self.vault.get(s["host"], s["user"]) or ""
                try:
                    from ..connector import ssh_connect, run_commands
                    client = ssh_connect(s["host"], s["user"] or "admin", password=pw or None)
                    result = run_commands(client, [cmd])
                    client.close()
                    output.insert(tk.END, result[:2000] + "\n")
                except Exception as e:
                    output.insert(tk.END, f"ERR: {e}\n")
                self.root.update()

        tk.Button(dialog, text="Esegui", bg="#2d5a27", fg="white",
                 relief=tk.FLAT, padx=20, command=run).pack(pady=6)

    def _bulk_backup(self):
        import tkinter.filedialog as fd
        from ..bulk import read_hosts, backup as bulk_backup

        hosts_file = fd.askopenfilename(title="File con lista host",
                                        filetypes=[("Text", "*.txt"), ("All", "*.*")],
                                        parent=self.root)
        if not hosts_file:
            return

        output_dir = fd.askdirectory(title="Cartella per backup", parent=self.root)
        if not output_dir:
            output_dir = str(Path.home() / ".netzunami" / "backups")

        hosts = read_hosts(hosts_file)
        if not hosts:
            messagebox.showerror("Errore", "Nessun host nel file")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Backup {len(hosts)} apparati")
        dialog.geometry("600x400")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)

        output = tk.Text(dialog, bg="#0a0a0a", fg="#d3d7cf", font=MONO_FONT,
                        relief=tk.FLAT, borderwidth=0)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        output.insert(tk.END, f"Backup di {len(hosts)} apparati...\n")
        self.root.update()

        def run():
            results = bulk_backup(hosts, output_dir, max_workers=5)
            ok = sum(1 for r in results if r["status"] == "ok")
            err = sum(1 for r in results if r["status"] == "error")
            for r in results:
                if r["status"] == "ok":
                    output.insert(tk.END, f"✓ {r['host']} → {Path(r['file']).name}\n")
                else:
                    output.insert(tk.END, f"✗ {r['host']}: {r['error']}\n")
                self.root.update()
            output.insert(tk.END, f"\nFatto: {ok} OK, {err} errori\n")
            self._update_status(f"Backup: {ok}/{len(hosts)}")

        threading.Thread(target=run, daemon=True).start()

    def _bulk_push(self):
        import tkinter.filedialog as fd
        from ..bulk import read_hosts, bulk_apply, render_template

        hosts_file = fd.askopenfilename(title="File con lista host",
                                        filetypes=[("Text", "*.txt"), ("All", "*.*")],
                                        parent=self.root)
        if not hosts_file:
            return

        template_file = fd.askopenfilename(title="Template comandi",
                                           filetypes=[("Text", "*.txt"), ("All", "*.*")],
                                           parent=self.root)
        if not template_file:
            return

        with open(template_file) as f:
            template = f.read()

        hosts = read_hosts(hosts_file)
        if not hosts:
            messagebox.showerror("Errore", "Nessun host nel file")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Push su {len(hosts)} apparati")
        dialog.geometry("600x450")
        dialog.configure(bg="#1a1a1a")
        dialog.transient(self.root)

        tk.Label(dialog, text="Anteprima template:", bg="#1a1a1a", fg="#d3d7cf",
                anchor="w").pack(fill=tk.X, padx=10, pady=4)

        preview = tk.Text(dialog, bg="#2a2a2a", fg="#d3d7cf", font=MONO_FONT,
                         height=6, relief=tk.FLAT, borderwidth=0)
        preview.pack(fill=tk.X, padx=10, pady=2)
        preview.insert(tk.END, template[:500])
        preview.config(state=tk.DISABLED)

        output = tk.Text(dialog, bg="#0a0a0a", fg="#d3d7cf", font=MONO_FONT,
                        relief=tk.FLAT, borderwidth=0)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        def run():
            if not messagebox.askyesno("Conferma", f"Pushare su {len(hosts)} apparati?"):
                return
            passwords = {s["host"]: (self.vault.get(s["host"], s["user"]) or "")
                        for s in hosts}
            results = bulk_apply(hosts, template, passwords=passwords, confirm=False)
            ok = sum(1 for r in results if r["status"] == "ok")
            for r in results:
                if r["status"] == "ok":
                    output.insert(tk.END, f"✓ {r['host']}\n")
                elif r["status"] == "error":
                    output.insert(tk.END, f"✗ {r['host']}: {r.get('error', '')}\n")
                self.root.update()
            output.insert(tk.END, f"\nFatto: {ok} OK, {len(results)-ok} falliti\n")

        btn_frame = tk.Frame(dialog, bg="#1a1a1a")
        btn_frame.pack(fill=tk.X, padx=10, pady=6)
        tk.Button(btn_frame, text="Esegui Push", bg="#2d5a27", fg="white",
                 relief=tk.FLAT, padx=20, command=lambda: threading.Thread(target=run, daemon=True).start()
                 ).pack(side=tk.LEFT, padx=4)

    def _start_listener(self):
        import tkinter.filedialog as fd
        log_path = fd.askopenfilename(title="Seleziona log sessione da monitorare",
                                      parent=self.root)
        if log_path:
            threading.Thread(
                target=self._run_listener,
                args=(log_path,),
                daemon=True,
            ).start()
            self._update_status(f"Listener attivo: {Path(log_path).name}")

    def _run_listener(self, log_path: str):
        from ..listener import listen_session
        listen_session(log_path, callback=self._on_finding_from_listener)

    def _on_finding_from_listener(self, finding, line: str):
        self.root.after(0, lambda: self._on_finding(
            {"severity": finding.severity, "title": finding.title, "detail": finding.detail,
             "suggestion": finding.suggestion},
            line,
        ))

    def _preferences(self):
        messagebox.showinfo("Preferenze", "Configurabile in ~/.netzunami/config.yaml")

    def _show_about(self):
        from .. import __version__
        messagebox.showinfo(
            "Netzunami",
            f"Netzunami v{__version__}\n\nNetwork config analyzer with AI\nPython + Tkinter + Paramiko",
        )

    def _show_shortcuts(self):
        shortcuts = """Shortcut:
  Ctrl+N   Nuova connessione
  Ctrl+Q   Quick connect
  Ctrl+T   Nuovo tab
  Ctrl+W   Chiudi tab
  Ctrl+C   Copia (nel terminale)
  Ctrl+V   Incolla (nel terminale)"""
        messagebox.showinfo("Shortcuts", shortcuts)

    def _update_status(self, extra: str = ""):
        pass

    def _on_close(self):
        if self.current_terminal:
            self.current_terminal.disconnect()
        self.vault.lock()
        self.root.destroy()

    def run(self):
        self.root.mainloop()
