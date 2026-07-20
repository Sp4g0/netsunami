# Netzunami — Network Config Analyzer AI

**Idea di: Sp4g0 — Prototipo v0.1.0 — bozza da testare**

## Concept

Terminale SSH intelligente (tipo PuTTY/SecureCRT) che analizza configurazioni di rete in tempo reale.

**Per chi è:**
- **Junior**: impara dalle best practice, capisce cosa controllare, evita errori comuni
- **Senior**: velocizza check, bulk change, non perde dettagli su decine di apparati

## Workflow Change Massivi

```
1. hosts.txt                   2. Da chat (AI)                   3. Push
┌──────────────┐              ┌──────────────┐                  ┌──────────┐
│ 10.0.0.1     │              │ interface    │                  │ Apparato │
│ 10.0.0.2     │     template │ {{port}}     │   netzunami      │    1 ✓   │
│ sw-01        │  ───────►    │  switchport  │  ──────────►     │    2 ✓   │
│ sw-02        │              │  mode access │                  │    3 ✓   │
└──────────────┘              │  ...         │                  └──────────┘
                              └──────────────┘
```

## CLI

```bash
# Backup massivo
netzunami bulk backup hosts.txt -o ~/backup/

# Push template con variabili
netzunami bulk push hosts.txt template.txt --var port=Gi0/1 --var vlan=100

# Salta conferma (-y)
netzunami bulk push hosts.txt template.txt -y

# Analisi offline
netzunami analyze show_run.cfg

# Connessione SSH + analisi live
netzunami ssh 10.0.0.1 -u admin

# GUI
python -m netzunami.gui
```

## GUI (Tkinter)

- Terminale colorato stile PuTTY/SecureCRT
- Pannello sessioni a sinistra
- Pannello NetSense AI a destra (findings live)
- Vault password crittografato
- Import sessioni CRT
- Backup massivo / Push template
- Shortcut: Ctrl+N, Ctrl+Q, Ctrl+T, Ctrl+W
