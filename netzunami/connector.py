import paramiko
import re
import time

VENDOR_PROMPTS = {
    "cisco": r"[>#]\s*$",
    "huawei": r"[>#]\s*$",
    "aethra": r"[>#]\s*$",
    "juniper": r"%\s*$",
}


def ssh_connect(
    host: str,
    user: str,
    key_path: str | None = None,
    password: str | None = None,
    port: int = 22,
    bastion: dict | None = None,
    timeout: int = 15,
) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if bastion:
        jump = paramiko.SSHClient()
        jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        jump_kw = {
            "hostname": bastion["host"],
            "username": bastion.get("user", user),
            "port": bastion.get("port", 22),
        }
        if bastion.get("key"):
            jump_kw["key_filename"] = bastion["key"]
        if password:
            jump_kw["password"] = password
        jump.connect(**jump_kw, timeout=timeout)

        transport = jump.get_transport()
        dest_addr = (host, port)
        local_addr = ("127.0.0.1", 0)
        channel = transport.open_channel(
            "direct-tcpip", dest_addr, local_addr, timeout=timeout
        )

        client_kw = {
            "hostname": host,
            "username": user,
            "sock": channel,
            "timeout": timeout,
        }
        if key_path:
            client_kw["key_filename"] = key_path
        if password:
            client_kw["password"] = password
        client.connect(**client_kw)
    else:
        client_kw = {
            "hostname": host,
            "username": user,
            "port": port,
            "timeout": timeout,
        }
        if key_path:
            client_kw["key_filename"] = key_path
        if password:
            client_kw["password"] = password
        client.connect(**client_kw)

    return client


def _recv_until_prompt(shell, prompt_re: str, timeout_sec: int = 15) -> str:
    output = ""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            data = shell.recv(65535).decode("utf-8", errors="replace")
            output += data
            if re.search(prompt_re, data, re.MULTILINE):
                break
        except:
            break
    return output


def detect_vendor(shell) -> str:
    shell.send("\n")
    time.sleep(1)
    try:
        banner = shell.recv(4096).decode("utf-8", errors="replace").lower()
    except:
        banner = ""

    if "huawei" in banner or "vrp" in banner:
        return "huawei"
    if "aethra" in banner:
        return "aethra"
    if "junos" in banner or "junipers" in banner or "juniper" in banner:
        return "juniper"
    return "cisco"


def _enable_and_wait(shell, prompt_re: str, enable_password: str | None = None):
    shell.send("enable\n")
    output = _recv_until_prompt(shell, prompt_re)
    if "password" in output.lower() and enable_password:
        shell.send(f"{enable_password}\n")
        output += _recv_until_prompt(shell, prompt_re)
    return output


def run_commands(
    client: paramiko.SSHClient,
    commands: list[str],
    vendor: str | None = None,
    enable: bool = True,
    enable_password: str | None = None,
) -> str:
    shell = client.invoke_shell()
    shell.settimeout(30)
    output = ""

    if vendor is None:
        vendor = detect_vendor(shell)

    prompt_re = VENDOR_PROMPTS.get(vendor, r"[>#]\s*$")

    if vendor == "huawei":
        shell.send("screen-length 0 temporary\n")
        _recv_until_prompt(shell, prompt_re)
        for cmd in commands:
            shell.send(f"{cmd}\n")
            output += _recv_until_prompt(shell, prompt_re)
        shell.send("quit\n")
        shell.close()
        return output

    if vendor == "aethra":
        if enable:
            output += _enable_and_wait(shell, prompt_re, enable_password)
        shell.send("terminal length 0\n")
        _recv_until_prompt(shell, prompt_re)
        for cmd in commands:
            shell.send(f"{cmd}\n")
            output += _recv_until_prompt(shell, prompt_re)
        shell.close()
        return output

    if vendor == "juniper":
        shell.send("set cli screen-length 0\n")
        _recv_until_prompt(shell, prompt_re)
        for cmd in commands:
            shell.send(f"{cmd}\n")
            output += _recv_until_prompt(shell, prompt_re)
        shell.close()
        return output

    if vendor == "cisco":
        if enable:
            output += _enable_and_wait(shell, prompt_re, enable_password)
        shell.send("terminal length 0\n")
        _recv_until_prompt(shell, prompt_re)
        for cmd in commands:
            shell.send(f"{cmd}\n")
            output += _recv_until_prompt(shell, prompt_re)

    shell.close()
    return output


def _parse_show_version(text: str) -> dict:
    info = {}
    m = re.search(r"ROM:.*\n.*\n(.+)", text)
    m = re.search(r"Cisco (.+?) (?:revision|processor|\(", text, re.IGNORECASE)
    if m:
        info["model"] = m.group(1).strip()
    m = re.search(r"Software, (.+?),", text, re.IGNORECASE)
    if m:
        info["ios_version"] = m.group(1).strip()
    m = re.search(r"(.+?) uptime is (.+)", text, re.IGNORECASE)
    if m:
        info["hostname"] = m.group(1).strip()
        info["uptime"] = m.group(2).strip()
    m = re.search(r"processor board ID (\S+)", text, re.IGNORECASE)
    if m:
        info["serial"] = m.group(1)
    m = re.search(r"with (\d+[KMG]? bytes?) of memory", text, re.IGNORECASE)
    if m:
        info["memory"] = m.group(1)
    return info


def _parse_show_processes_cpu(text: str) -> str:
    m = re.search(r"CPU utilization for five seconds: (\S+%?\d*\.?\d*)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"CPU utilization for five seconds:? (\S+)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"five seconds: (\S+%)", text)
    return m.group(1) if m else ""


def fetch_device_info(
    client: paramiko.SSHClient,
    host: str,
    enable_password: str | None = None,
) -> "DeviceInfo":
    from .models import DeviceInfo

    ver = run_commands(client, ["show version"], enable_password=enable_password)
    info = _parse_show_version(ver)
    cpu = ""
    try:
        cpu_out = run_commands(client, ["show processes cpu"], enable_password=enable_password)
        cpu = _parse_show_processes_cpu(cpu_out)
    except Exception:
        pass

    return DeviceInfo(
        hostname=info.get("hostname", host),
        model=info.get("model", ""),
        ios_version=info.get("ios_version", ""),
        uptime=info.get("uptime", ""),
        cpu=cpu,
        memory=info.get("memory", ""),
        serial=info.get("serial", ""),
    )
