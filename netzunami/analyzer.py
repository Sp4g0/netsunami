import os
import re
import numpy as np
from pathlib import Path
from .models import Finding, Severity, AnalysisResult, ConfigBlock
from .parser import parse_running_config
from .embedder import embed
from .indexer import index_manuals, search


HUAWEI_ISSUES = [
    {
        "pattern": r"undo shutdown",
        "severity": Severity.INFO,
        "title": "Interfaccia abilitata",
        "detail": "Interfaccia in stato di up.",
        "suggestion": "",
    },
    {
        "pattern": r"shutdown",
        "severity": Severity.INFO,
        "title": "Interfaccia disabilitata",
        "detail": "Interfaccia in shutdown. Verificare se intenzionale.",
        "suggestion": "Usare 'undo shutdown' per abilitare.",
    },
    {
        "pattern": r"interface (GigabitEthernet|XGigabitEthernet|Eth-Trunk)\S+",
        "severity": Severity.LOW,
        "title": "Interfaccia configurata",
        "detail": "Interfaccia fisica configurata.",
        "suggestion": "",
    },
    {
        "pattern": r"port link-type (access|trunk|hybrid)",
        "severity": Severity.LOW,
        "title": "Link type configurato",
        "detail": "Tipo di porta configurato su interfaccia.",
        "suggestion": "Verificare consistenza con dispositivo opposto.",
    },
    {
        "pattern": r"port trunk allow-pass vlan",
        "severity": Severity.MEDIUM,
        "title": "VLAN trunk permesse",
        "detail": "VLAN permesse su trunk. Verificare che siano le minime necessarie.",
        "suggestion": "Limitare le VLAN al minimo indispensabile (principio least privilege).",
    },
    {
        "pattern": r"port trunk allow-pass vlan all",
        "severity": Severity.HIGH,
        "title": "Tutte le VLAN permesse sul trunk",
        "detail": "Tutte le VLAN sono permesse su questo trunk. Rischio di VTP/VLAN hopping.",
        "suggestion": "Specificare solo le VLAN necessarie: 'port trunk allow-pass vlan <vlan-id>'",
    },
    {
        "pattern": r"stp mode (mstp|rstp|stp)",
        "severity": Severity.LOW,
        "title": "STP mode configurato",
        "detail": "Modalità STP configurata.",
        "suggestion": "Usare MSTP per reti con molte VLAN, RSTP per semplicità.",
    },
    {
        "pattern": r"stp bpdu-protection",
        "severity": Severity.MEDIUM,
        "title": "BPDU protection attiva",
        "detail": "Protezione BPDU su edge port.",
        "suggestion": "",
    },
    {
        "pattern": r"undo stp enable",
        "severity": Severity.CRITICAL,
        "title": "STP disabilitato!",
        "detail": "Spanning Tree disabilitato. Rischio di loop di layer 2.",
        "suggestion": "Riabilitare STP con 'stp enable' o configurare loop-detection.",
    },
    {
        "pattern": r"ip route-static 0\.0\.0\.0\s+0",
        "severity": Severity.MEDIUM,
        "title": "Default route statica",
        "detail": "Rotta di default statica configurata.",
        "suggestion": "Verificare next-hop raggiungibile. Considerare tracking.",
    },
    {
        "pattern": r"ip route-static 0\.0\.0\.0\s+0\s+\S+",
        "severity": Severity.CRITICAL,
        "title": "Default route senza tracking",
        "detail": "Rotta di default statica senza track/BFD. Se il next-hop cade, traffico perso.",
        "suggestion": "Configurare track con 'ip route-static 0.0.0.0 0 <next-hop> track <n>'",
    },
    {
        "pattern": r"bgp \d+",
        "severity": Severity.LOW,
        "title": "BGP configurato",
        "detail": "Processo BGP attivo.",
        "suggestion": "",
    },
    {
        "pattern": r"peer \S+ as-number",
        "severity": Severity.MEDIUM,
        "title": "BGP neighbor configurato",
        "detail": "Peer BGP definito.",
        "suggestion": "Verificare reachabilità e stato sessione BGP.",
    },
    {
        "pattern": r"ospf \d+",
        "severity": Severity.LOW,
        "title": "OSPF configurato",
        "detail": "Processo OSPF attivo.",
        "suggestion": "",
    },
    {
        "pattern": r"ospf \d+ router-id (\d+\.\d+\.\d+\.\d+)",
        "severity": Severity.MEDIUM,
        "title": "OSPF router-id configurato",
        "detail": "Router-id OSPF configurato manualmente. Buona pratica.",
        "suggestion": "",
    },
    {
        "pattern": r"vlan \d+",
        "severity": Severity.INFO,
        "title": "VLAN configurata",
        "detail": "VLAN presente.",
        "suggestion": "",
    },
    {
        "pattern": r"acl \d+",
        "severity": Severity.LOW,
        "title": "ACL configurata",
        "detail": "Access-list configurata.",
        "suggestion": "",
    },
    {
        "pattern": r"acl \d+ permit ip any any",
        "severity": Severity.HIGH,
        "title": "ACL permissiva (permit ip any any)",
        "detail": "ACL con permesso totale a fondo. Valutare se necessaria.",
        "suggestion": "Specificare sorgenti e destinazioni più restrittive.",
    },
    {
        "pattern": r"snmp-agent community read|write",
        "severity": Severity.MEDIUM,
        "title": "SNMP community configurata",
        "detail": "Community SNMP configurata.",
        "suggestion": "Limitare con ACL: 'snmp-agent community <string> acl <num>'",
    },
    {
        "pattern": r"snmp-agent sys-info version v1",
        "severity": Severity.HIGH,
        "title": "SNMPv1 attivo",
        "detail": "SNMP versione 1 è insicura e deprecata.",
        "suggestion": "Usare SNMPv3: 'snmp-agent sys-info version v3'",
    },
    {
        "pattern": r"ntp unicast-server",
        "severity": Severity.LOW,
        "title": "NTP configurato",
        "detail": "Server NTP configurato.",
        "suggestion": "Verificare sincronizzazione con 'display ntp status'",
    },
    {
        "pattern": r"user-interface (vty|console)",
        "severity": Severity.LOW,
        "title": "User interface configurata",
        "detail": "Accesso VTY/Console configurato.",
        "suggestion": "",
    },
    {
        "pattern": r"local-user privilege level 15",
        "severity": Severity.MEDIUM,
        "title": "Utente privilege 15",
        "detail": "Utente locale con privilegi massimi.",
        "suggestion": "Usare AAA e privilegi granulari quando possibile.",
    },
    {
        "pattern": r"aaa",
        "severity": Severity.LOW,
        "title": "AAA configurato",
        "detail": "Autenticazione AAA configurata.",
        "suggestion": "",
    },
    {
        "pattern": r"undo http server",
        "severity": Severity.INFO,
        "title": "HTTP server disabilitato",
        "detail": "HTTP server disabilitato. Buona pratica.",
        "suggestion": "",
    },
    {
        "pattern": r"http server enable",
        "severity": Severity.HIGH,
        "title": "HTTP server abilitato",
        "detail": "HTTP server attivo. Vettore di attacco.",
        "suggestion": "Disabilitare con 'undo http server' o usare solo HTTPS.",
    },
    {
        "pattern": r"lldp enable",
        "severity": Severity.LOW,
        "title": "LLDP abilitato",
        "detail": "LLDP attivo sull'interfaccia.",
        "suggestion": "",
    },
    {
        "pattern": r"loopback-detect enable",
        "severity": Severity.INFO,
        "title": "Loop detection attiva",
        "detail": "Rilevamento loop abilitato. Buona pratica.",
        "suggestion": "",
    },
    {
        "pattern": r"dhcp snooping enable",
        "severity": Severity.MEDIUM,
        "title": "DHCP snooping attivo",
        "detail": "Protezione DHCP snooping attiva. Buona pratica.",
        "suggestion": "",
    },
    {
        "pattern": r"mac-address (flapping|blackhole)",
        "severity": Severity.MEDIUM,
        "title": "MAC flapping/blackhole",
        "detail": "Configurazione MAC speciale presente. Verificare motivo.",
        "suggestion": "",
    },
    {
        "pattern": r"port-security enable",
        "severity": Severity.MEDIUM,
        "title": "Port security attiva",
        "detail": "Port security abilitata sull'interfaccia.",
        "suggestion": "Verificare il limite di MAC e l'azione in caso di violazione.",
    },
    {
        "pattern": r"display logbuffer",
        "severity": Severity.INFO,
        "title": "Log buffer presente",
        "detail": "Log di sistema disponibile per diagnostica.",
        "suggestion": "Usare 'display logbuffer reverse' per ultimi eventi.",
    },
]


AETHRA_ISSUES = [
    {
        "pattern": r"no shutdown",
        "severity": Severity.INFO,
        "title": "Interfaccia abilitata",
        "detail": "Porta attiva.",
        "suggestion": "",
    },
    {
        "pattern": r"shutdown",
        "severity": Severity.INFO,
        "title": "Interfaccia disabilitata",
        "detail": "Porta in shutdown. Verificare se intenzionale.",
        "suggestion": "",
    },
    {
        "pattern": r"ip route 0\.0\.0\.0 0\.0\.0\.0 (\S+)",
        "severity": Severity.CRITICAL,
        "title": "Default route senza tracking",
        "detail": "Rotta di default statica. Se next-hop cade, traffico blackholed.",
        "suggestion": "Valutare floating static con metric o IP SLA.",
    },
    {
        "pattern": r"interface (Gi|Te|Fa|Eth|Po)",
        "severity": Severity.LOW,
        "title": "Interfaccia configurata",
        "detail": "Interfaccia presente in configurazione.",
        "suggestion": "",
    },
    {
        "pattern": r"snmp community (\S+) (ro|rw)",
        "severity": Severity.MEDIUM,
        "title": "SNMP community",
        "detail": "Community SNMP senza ACL restrittiva.",
        "suggestion": "Aggiungere ACL: 'snmp community <string> ro <acl>'",
    },
    {
        "pattern": r"ntp server",
        "severity": Severity.LOW,
        "title": "NTP configurato",
        "detail": "Server NTP presente.",
        "suggestion": "",
    },
    {
        "pattern": r"username (\S+) privilege 15",
        "severity": Severity.MEDIUM,
        "title": "Utente privilege 15",
        "detail": "Utente locale con privilegi massimi.",
        "suggestion": "Usare AAA se disponibile.",
    },
    {
        "pattern": r"enable password",
        "severity": Severity.MEDIUM,
        "title": "Enable password in chiaro",
        "detail": "Password enable non crittografata (type 7).",
        "suggestion": "Usare 'enable secret' con hash (type 8/9).",
    },
    {
        "pattern": r"ip http server",
        "severity": Severity.HIGH,
        "title": "HTTP server attivo",
        "detail": "HTTP server abilitato. Risk.",
        "suggestion": "Disabilitare con 'no ip http server'.",
    },
    {
        "pattern": r"spanning-tree (portfast|bpduguard)",
        "severity": Severity.MEDIUM,
        "title": "STP edge protection",
        "detail": "Portfast/BPDUGuard configurato su porta.",
        "suggestion": "",
    },
    {
        "pattern": r"switchport mode (access|trunk)",
        "severity": Severity.LOW,
        "title": "Switchport mode",
        "detail": "Modalità porta switch configurata.",
        "suggestion": "",
    },
    {
        "pattern": r"switchport trunk allowed vlan (\d+)",
        "severity": Severity.MEDIUM,
        "title": "VLAN su trunk",
        "detail": "VLAN permesse sul trunk.",
        "suggestion": "Verificare che non ci siano VLAN non necessarie.",
    },
    {
        "pattern": r"no aaa new-model",
        "severity": Severity.LOW,
        "title": "AAA non configurato",
        "detail": "AAA non presente. Autenticazione locale.",
        "suggestion": "",
    },
    {
        "pattern": r"ip domain-name",
        "severity": Severity.INFO,
        "title": "Domain name configurato",
        "detail": "Dominio configurato.",
        "suggestion": "",
    },
]


COMMON_ISSUES = {
    "cisco": [
        {
            "pattern": r"ip mtu (\d+)",
            "severity": Severity.MEDIUM,
            "title": "Configurazione MTU",
            "detail": "MTU configurato a livello di interfaccia. Verificare coerenza su entrambi i lati del link.",
            "suggestion": "Verificare MTU match su link adjacency. Usare 'show interface' per conferma.",
        },
        {
            "pattern": r"channel-group (\d+) mode (active|passive|on)",
            "severity": Severity.LOW,
            "title": "Port-channel configurato",
            "detail": "Port-channel attivo. Verificare consistenza membri su entrambi i lati.",
            "suggestion": "Verificare 'show etherchannel summary' per tutti i membri attivi.",
        },
        {
            "pattern": r"no shutdown",
            "severity": Severity.INFO,
            "title": "Interfaccia abilitata",
            "detail": "Interfaccia in stato 'no shutdown'. OK.",
            "suggestion": "",
        },
        {
            "pattern": r"shutdown",
            "severity": Severity.INFO,
            "title": "Interfaccia disabilitata",
            "detail": "Interfaccia in stato 'shutdown'. Verifica se intenzionale.",
            "suggestion": "Usare 'no shutdown' per abilitare.",
        },
        {
            "pattern": r"spanning-tree (bpduguard|portfast)",
            "severity": Severity.MEDIUM,
            "title": "STP Edge/BPDUGuard configurato",
            "detail": "Protezione STP su porta access/edge.",
            "suggestion": "Verificare che la porta sia realmente un edge port.",
        },
        {
            "pattern": r"vlan (\d+)",
            "severity": Severity.LOW,
            "title": "VLAN configurata",
            "detail": "VLAN presente in configurazione.",
            "suggestion": "",
        },
        {
            "pattern": r"ip route 0\.0\.0\.0 0\.0\.0\.0",
            "severity": Severity.INFO,
            "title": "Default route presente",
            "detail": "Rotta di default configurata globalmente.",
            "suggestion": "Verificare next-hop raggiungibile.",
        },
        {
            "pattern": r"ip route 0\.0\.0\.0 0\.0\.0\.0 (\S+)",
            "severity": Severity.CRITICAL,
            "title": "Default route senza tracking",
            "detail": "Rotta di default senza IP SLA/object tracking. Se il next-hop cade, il traffico viene blackholed.",
            "suggestion": "Aggiungere 'track' object e 'ip route 0.0.0.0 0.0.0.0 <next-hop> track <n>'",
        },
        {
            "pattern": r"router ospf (\d+)",
            "severity": Severity.LOW,
            "title": "OSPF configurato",
            "detail": "Processo OSPF attivo.",
            "suggestion": "",
        },
        {
            "pattern": r"neighbor (\S+) remote-as",
            "severity": Severity.MEDIUM,
            "title": "BGP neighbor configurato",
            "detail": "Peer BGP definito.",
            "suggestion": "Verificare reachability e stato sessione BGP.",
        },
        {
            "pattern": r"ip access-list extended",
            "severity": Severity.LOW,
            "title": "ACL extended presente",
            "detail": "Access-list extended configurata.",
            "suggestion": "",
        },
        {
            "pattern": r"no ip domain-lookup",
            "severity": Severity.INFO,
            "title": "Domain lookup disabilitato",
            "detail": "DNS lookup disabilitato. Buona pratica.",
            "suggestion": "",
        },
        {
            "pattern": r"ip domain-name\s+\S+",
            "severity": Severity.INFO,
            "title": "Domain name configurato",
            "detail": "Domain name presente. Usato per generazione certificati e chiavi.",
            "suggestion": "",
        },
        {
            "pattern": r"crypto pki",
            "severity": Severity.MEDIUM,
            "title": "PKI/Certificati configurati",
            "detail": "Infrastruttura a chiave pubblica presente.",
            "suggestion": "Verificare scadenza certificati e trustpoint.",
        },
        {
            "pattern": r"ntp server",
            "severity": Severity.LOW,
            "title": "NTP configurato",
            "detail": "Server NTP configurato.",
            "suggestion": "Verificare sincronizzazione con 'show ntp status'.",
        },
        {
            "pattern": r"ntp server (\S+)",
            "severity": Severity.LOW,
            "title": "NTP source tracking",
            "detail": "Verificare che il source IP per NTP sia configurato con 'ntp source <interface>'",
            "suggestion": "Se non configurato, aggiungere 'ntp source Loopback0'",
        },
        {
            "pattern": r"username (\S+) privilege 15",
            "severity": Severity.MEDIUM,
            "title": "Utente privilege 15",
            "detail": "Utente con privilegi massimi. Valutare se necessario.",
            "suggestion": "Usare privilege level appropriato o AAA con autorizzazione per-command.",
        },
        {
            "pattern": r"aaa new-model",
            "severity": Severity.LOW,
            "title": "AAA model attivo",
            "detail": "AAA new-model configurato.",
            "suggestion": "",
        },
        {
            "pattern": r"service password-encryption",
            "severity": Severity.LOW,
            "title": "Password encryption attiva",
            "detail": "Password encryption (type 7) attiva.",
            "suggestion": "Considerare type 8/9 (SHA256/SCRYPT) per password più sicure.",
        },
        {
            "pattern": r"enable secret",
            "severity": Severity.INFO,
            "title": "Enable secret configurato",
            "detail": "Enable password protetta da hash. Buona pratica.",
            "suggestion": "",
        },
        {
            "pattern": r"no enable secret",
            "severity": Severity.CRITICAL,
            "title": "Enable secret NON configurato",
            "detail": "Manca protezione su accesso privilegiato.",
            "suggestion": "Configurare 'enable secret <password>'",
        },
        {
            "pattern": r"snmp-server community (\S+) (RO|RW)",
            "severity": Severity.MEDIUM,
            "title": "SNMP community",
            "detail": "Community SNMP configurata. Risk se non ristretta da ACL.",
            "suggestion": "Aggiungere ACL: 'snmp-server community XXXX RO <acl>'",
        },
        {
            "pattern": r"ip http server",
            "severity": Severity.HIGH,
            "title": "HTTP server attivo",
            "detail": "HTTP server abilitato. Vettore di attacco se non necessario.",
            "suggestion": "Disabilitare con 'no ip http server' o usare solo HTTPS con ACL.",
        },
        {
            "pattern": r"ip http secure-server",
            "severity": Severity.LOW,
            "title": "HTTPS server attivo",
            "detail": "HTTPS server abilitato. Preferibile a HTTP.",
            "suggestion": "",
        },
        {
            "pattern": r"ip ssh version 2",
            "severity": Severity.INFO,
            "title": "SSHv2 configurato",
            "detail": "SSH versione 2. OK.",
            "suggestion": "",
        },
        {
            "pattern": r"ip ssh version 1",
            "severity": Severity.HIGH,
            "title": "SSHv1 attivo",
            "detail": "SSH versione 1 è insicura e deprecata.",
            "suggestion": "Configurare 'ip ssh version 2'",
        },
    ]
}


def analyze_with_rules(blocks: list[ConfigBlock], vendor: str = "cisco") -> list[Finding]:
    findings: list[Finding] = []
    rules = COMMON_ISSUES.get(vendor, [])

    for block in blocks:
        full_text = "\n".join(line.text for line in block.lines)

        for rule in rules:
            matches = re.findall(rule["pattern"], full_text, re.IGNORECASE)
            if matches:
                matched_lines = [
                    line.number
                    for line in block.lines
                    if re.search(rule["pattern"], line.text, re.IGNORECASE)
                ]
                findings.append(
                    Finding(
                        severity=rule["severity"],
                        title=rule["title"],
                        detail=rule["detail"],
                        config_lines=matched_lines,
                        suggestion=rule["suggestion"],
                    )
                )

    return findings


def analyze_with_knowledge(
    blocks: list[ConfigBlock], index, metadata: list[dict], model_name: str = "all-MiniLM-L6-v2", top_k: int = 3
) -> list[Finding]:
    findings: list[Finding] = []
    seen = set()

    for block in blocks:
        block_text = "\n".join(line.text for line in block.lines)
        results = search(index, metadata, block_text, model_name, top_k)

        for meta, score in results:
            if score < 0.6:
                continue
            key = (meta["source"], meta["chunk"])
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"Manuale: {meta['source']} (sez.{meta['chunk']})",
                    detail=f"Similarità: {score:.2f} — {meta['text'][:150]}",
                    similarity=score,
                )
            )

    return findings
