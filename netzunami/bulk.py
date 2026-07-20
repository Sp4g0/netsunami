"""Bulk operations: mass backup, template apply, diff"""

import os
import re
import json
import time
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .connector import ssh_connect, run_commands
from .config import Config


def read_hosts(hosts_file: str) -> list[dict]:
    hosts = []
    with open(hosts_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            host = parts[0].strip()
            user = parts[1].strip() if len(parts) > 1 else "admin"
            port = int(parts[2].strip()) if len(parts) > 2 else 22
            hosts.append({"host": host, "user": user, "port": port})
    return hosts


def backup(hosts: list[dict], output_dir: str | None = None, max_workers: int = 5):
    if output_dir is None:
        output_dir = str(Path.home() / ".netzunami" / "backups")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    results = []

    def _backup_one(entry: dict):
        try:
            client = ssh_connect(entry["host"], entry["user"], port=entry["port"])
            raw = run_commands(client, ["show running-config"])
            client.close()

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"{entry['host']}_{ts}.cfg"
            fpath = out / fname
            with open(fpath, "w") as f:
                f.write(raw)
            return {"host": entry["host"], "status": "ok", "file": str(fpath)}
        except Exception as e:
            return {"host": entry["host"], "status": "error", "error": str(e)}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_backup_one, e): e for e in hosts}
        for f in as_completed(futures):
            results.append(f.result())

    return results


def apply_template(
    host: str,
    user: str,
    template: str,
    port: int = 22,
    password: str = "",
    vendor: str = "cisco",
) -> dict:
    try:
        client = ssh_connect(host, user, port=port, password=password or None)
        commands = [line.strip() for line in template.splitlines()
                   if line.strip() and not line.strip().startswith("#")]
        output = run_commands(client, commands, vendor=vendor)
        client.close()
        return {"host": host, "status": "ok", "output": output[:500]}
    except Exception as e:
        return {"host": host, "status": "error", "error": str(e)}


def bulk_apply(
    hosts: list[dict],
    template: str,
    passwords: dict[str, str] | None = None,
    max_workers: int = 5,
    confirm: bool = True,
) -> list[dict]:
    results = []
    passwords = passwords or {}

    def _apply(entry: dict):
        pw = passwords.get(entry["host"], "")
        return apply_template(entry["host"], entry["user"], template, entry["port"], pw)

    if confirm:
        print(f"\n  Hosts: {len(hosts)}")
        print(f"  Comandi:\n{template}\n")
        resp = input("  Confermi push? [y/N]: ")
        if resp.lower() != "y":
            return [{"host": e["host"], "status": "cancelled"} for e in hosts]

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_apply, e): e for e in hosts}
        for f in as_completed(futures):
            results.append(f.result())

    return results


def read_excel(excel_path: str, sheet: str | int = 0) -> list[dict]:
    try:
        import pandas as pd
    except ImportError:
        print("  Serve pandas: pip install pandas openpyxl")
        return []

    df = pd.read_excel(excel_path, sheet_name=sheet, dtype=str)
    df = df.fillna("")
    return df.to_dict(orient="records")


def render_template(template: str, variables: dict[str, str]) -> str:
    for key, val in variables.items():
        template = template.replace(f"{{{{{key}}}}}", val)
    return template


def push_from_excel(
    excel_path: str,
    template: str,
    host_column: str = "Host",
    sheet: str | int = 0,
    passwords: dict[str, str] | None = None,
    max_workers: int = 5,
    confirm: bool = True,
) -> list[dict]:
    rows = read_excel(excel_path, sheet)
    if not rows:
        return []

    hosts = []
    for row in rows:
        host = row.get(host_column, "").strip()
        if not host:
            continue
        user = row.get("User", "admin")
        port = int(row.get("Port", "22"))
        hosts.append({"host": host, "user": user, "port": port, "vars": row})

    results = []
    passwords = passwords or {}

    def _apply(entry: dict):
        rendered = render_template(template, entry["vars"])
        pw = passwords.get(entry["host"], "")
        return apply_template(entry["host"], entry["user"], rendered, entry["port"], pw)

    if confirm:
        print(f"\n  Righe Excel: {len(rows)}")
        print(f"  Host column: {host_column}")
        print(f"  Template:\n{template}\n")
        resp = input("  Confermi push? [y/N]: ")
        if resp.lower() != "y":
            return [{"host": e["host"], "status": "cancelled"} for e in hosts]

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_apply, e): e for e in hosts}
        for f in as_completed(futures):
            results.append(f.result())

    return results
