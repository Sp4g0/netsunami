import re
from .models import ConfigLine, ConfigBlock


BLOCK_HEADERS = {
    "cisco": [
        r"^interface\s",
        r"^router\s",
        r"^vlan\s",
        r"^port-channel\s",
        r"^line\s",
        r"^ip\s+access-list\s",
        r"^route-map\s",
        r"^prefix-list\s",
        r"^community-list\s",
        r"^class-map\s",
        r"^policy-map\s",
        r"^control-plane\s",
        r"^spanning-tree\s",
        r"^snmp-server\s",
        r"^ntp\s",
        r"^logging\s",
        r"^banner\s",
        r"^username\s",
        r"^aaa\s",
        r"^crypto\s",
    ],
    "huawei": [
        r"^interface\s",
        r"^vlan\s",
        r"^vlanif\s",
        r"^bgp\s",
        r"^ospf\s",
        r"^isis\s",
        r"^rip\s",
        r"^acl\s",
        r"^traffic\S+",
        r"^qos\s",
        r"^ip\s+route-static\s",
        r"^ip\s+prefix-list\s",
        r"^route-policy\s",
        r"^snmp-agent\s",
        r"^ntp\s",
        r"^info-center\s",
        r"^stp\s",
        r"^lldp\s",
        r"^mac-address\s",
        r"^user-interface\s",
        r"^local-user\s",
        r"^radius-server\s",
        r"^acl\s",
    ],
    "juniper": [
        r"^\s+interface\s",
        r"^\s+policy-statement\s",
        r"^\s+community\s",
        r"^\s+prefix-list\s",
        r"^\s+bgp\s",
        r"^\s+ospf\s",
        r"^\s+isis\s",
        r"^\s+vlan\s",
        r"^\s+firewall\s",
        r"^\s+nat\s",
        r"^\s+snmp\s",
        r"^\s+syslog\s",
        r"^\s+ntp\s",
        r"^\s+security\s",
    ],
}


def parse_block(config_text: str, patterns: list[str], comment_chars: tuple[str, ...] = ("!",)) -> list[ConfigBlock]:
    blocks: list[ConfigBlock] = []
    current_block: ConfigBlock | None = None
    lines = config_text.splitlines()
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(comment_chars):
            continue

        is_header = any(p.match(stripped) for p in compiled)

        if is_header:
            if current_block and current_block.lines:
                blocks.append(current_block)
            current_block = ConfigBlock(name=stripped)
            current_block.lines.append(
                ConfigLine(number=i + 1, text=stripped, indent=0)
            )
        elif current_block is not None:
            indent = len(line) - len(line.lstrip())
            current_block.lines.append(
                ConfigLine(number=i + 1, text=stripped, indent=indent)
            )

    if current_block and current_block.lines:
        blocks.append(current_block)

    return blocks


def parse_cisco(config_text: str) -> list[ConfigBlock]:
    return parse_block(config_text, BLOCK_HEADERS["cisco"], ("!",))


def parse_huawei(config_text: str) -> list[ConfigBlock]:
    return parse_block(config_text, BLOCK_HEADERS["huawei"], ("#", "!"))


def parse_juniper(config_text: str) -> list[ConfigBlock]:
    blocks = []
    current = ConfigBlock(name="root")
    depth = 0
    for i, line in enumerate(config_text.splitlines()):
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        indent = len(line) - len(line.lstrip())
        if "{" in stripped:
            blocks.append(current)
            name = stripped.replace("{", "").strip().split("\n")[0]
            current = ConfigBlock(name=name, vendor="juniper")
            current.lines.append(ConfigLine(number=i + 1, text=stripped, indent=indent))
            depth += 1
        elif "}" in stripped:
            if current.lines:
                blocks.append(current)
            current = ConfigBlock(name="root", vendor="juniper")
            depth = max(0, depth - 1)
        else:
            current.lines.append(ConfigLine(number=i + 1, text=stripped, indent=indent))
    if current.lines and current.name != "root":
        blocks.append(current)
    return blocks


def parse_running_config(config_text: str, vendor: str = "cisco") -> list[ConfigBlock]:
    if vendor == "huawei":
        return parse_huawei(config_text)
    if vendor == "juniper":
        return parse_juniper(config_text)
    return parse_cisco(config_text)
