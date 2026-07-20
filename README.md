# 🌊 Netzunami

> **Terminale SSH intelligente per network engineer.**
> Analisi running-config in tempo reale, AI embeddings, change massivi, multi-vendor.

---

## 🚀 Perché Netzunami?

| 👶 **Junior** | 👨‍💼 **Senior** |
|:---|:---|
| Impari le best practice mentre lavori | Velocizzi audit e change su N apparati |
| Non sbagli configurazioni di base | Non perdi dettagli su decine di device |
| L'AI ti suggerisce cosa controllare | Bulk push da Excel in un comando |

---

## ✨ Cosa fa

| Comando | Cosa fa |
|---------|---------|
| `netzunami ssh <host>` | 🔌 SSH + dump config + analisi immediata |
| `netzunami analyze <file>` | 📋 Analisi offline di una running-config |
| `netzunami bulk backup hosts.txt` | 💾 Backup massivo di N apparati |
| `netzunami bulk push hosts.txt template.txt` | 📤 Push comandi su N apparati |
| `netzunami bulk excel report.xlsx template.txt` | 📊 Push da Excel (colonne → variabili) |
| `netzunami listen <log>` | 👂 Ascolta sessione live e suggerisce |
| `netzunami index <dir>` | 📚 Indicizza manuali PDF in knowledge base |
| `python -m netzunami.gui` | 🖥️ GUI stile SecureCRT |
| `netzunami info` | ℹ️ Stato: vettori, modello, config |

---

## 🏗️ Installazione

```bash
# Base (sklearn + paramiko) — ~50MB, funziona subito
pip install -e .

# + AI (sentence-transformers, FAISS, PyMuPDF) — ~2GB
pip install -e ".[ai]"

# + Excel (pandas, openpyxl)
pip install pandas openpyxl

# Avvia GUI
python -m netzunami.gui
```

---

## 🔌 Esempi rapidi

```bash
# Backup di 10 switch
echo -e "sw-01\nsw-02\nsw-03" > hosts.txt
netzunami bulk backup hosts.txt -o ~/backup/

# Push template da Excel
netzunami bulk excel report.xlsx template.txt --host-col Hostname

# Analisi running-config
netzunami analyze show_run.cfg

# Connessione via bastion
netzunami ssh core-sw-01 -u admin
```

---

## 🧠 Multi-Vendor

| Vendor | Parsing | Regole |
|--------|---------|--------|
| Cisco IOS/XE | ✅ | 25 regole |
| Cisco NX-OS | ✅ | _in arrivo_ |
| Huawei VRP | ✅ | _in arrivo_ |
| Juniper JunOS | ✅ | _in arrivo_ |

---

## ⚙️ Workflow Change Massivi

```
📄 hosts.txt / 📊 report.xlsx
        │
        ▼
📝 template.txt  (con {{Colonna}} dal tuo Excel)
        │
        ▼
🌊 netzunami bulk push / excel
        │
        ├── ✅ sw-01  〰️ interface Gi0/1, vlan 100
        ├── ✅ sw-02  〰️ interface Gi0/2, vlan 200
        └── ❌ sw-03  〰️ connection timeout
```

---

## 🛡️ Privacy & Sicurezza

- **Zero cloud** — tutto gira sul tuo laptop
- **Zero telemetria** — nessuna chiamata esterna
- **Vault crittografato** (Fernet) — password al sicuro
- **Niente admin** — `pip install` come user, tkinter built-in

---

## 🗺️ Roadmap

- [x] CLI + GUI tkinter
- [x] SSH con bastion/jump host
- [x] 25 regole Cisco (CRITICAL → INFO)
- [x] Backup massivo + push template
- [x] Lettura Excel (colonne → variabili template)
- [x] Multi-vendor parser (Cisco, Huawei, Juniper)
- [ ] Regole vendor-specific (Huawei, Juniper)
- [ ] Training incrementale da feedback
- [ ] Change massivi con rollback pianificato
- [ ] Riconoscimento automatico vendor (da prompt SSH)

---

## 📦 Dipendenze minime

- `paramiko` — SSH
- `scikit-learn` — embedding Tfidf
- `cryptography` — vault password
- `click` + `rich` — CLI
- `tkinter` — GUI (built-in)

---

## 👤 Autore

**Ideato da:** Sp4g0  
**Licenza:** MIT
