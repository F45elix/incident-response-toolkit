# 🚨 Incident Response & Digital Forensics Toolkit

> **Skills demonstrated:** Incident Response (NIST 800-61r2) · Digital Forensics · IOC Extraction · STIX 2.1 · Threat Intelligence · Malware Analysis · Evidence Chain-of-Custody · Python

An automated Incident Response toolkit implementing the full **NIST SP 800-61r2** IR lifecycle — from evidence collection and IOC extraction through to STIX 2.1 threat intelligence export. Built to demonstrate skills sought in senior SOC, IR, and threat intelligence roles in Australia and the UK.

---

## 📋 Why This Project

Top skills from sponsored IR/SOC roles on SEEK (AU) and CyberSecurityJobs (UK):

| Skill | Implementation |
|---|---|
| Incident Response methodology | Full NIST 800-61r2 lifecycle phases |
| Digital forensics | Volatile evidence collection with hash integrity |
| Malware analysis | IOC extraction, STIX indicators, C2 identification |
| Threat intelligence | STIX 2.1 bundle export for TIP ingestion |
| Scripting (Python) | Full automation of IR steps |
| Chain-of-custody | Immutable audit log per artefact |
| Compliance | GDPR 72-hour notification, legal hold guidance |

---

## 🚀 Quick Start

```bash
git clone https://github.com/F45elix/incident-response-toolkit.git
cd incident-response-toolkit
pip install -r requirements.txt

# Full ransomware IR simulation
python main.py --demo

# Run a specific playbook
python main.py --playbook phishing

# Extract IOCs from a threat report
python main.py --extract-iocs --input threat_report.txt

# Run tests
pytest tests/ -v
```

---

## 🔄 NIST IR Lifecycle Implementation

```
┌─────────────────────────────────────────────────────────┐
│  1. Preparation    │  Playbooks, runbooks, tooling      │
│  2. Detection      │  IOC extraction, alert triage      │
│  3. Containment    │  Automated playbook execution      │
│  4. Eradication    │  Malware removal steps             │
│  5. Recovery       │  Backup restoration guidance       │
│  6. Post-Incident  │  STIX export, lessons learned      │
└─────────────────────────────────────────────────────────┘
```

---

## 📚 Playbooks Included

| Playbook | Steps | Severity |
|---|---|---|
| `ransomware` | 10 steps | P1-CRITICAL |
| `phishing` | 10 steps | P2-HIGH |
| `insider_threat` | 10 steps | P1-CRITICAL |

---

## 🔬 IOC Extraction Capabilities

| IOC Type | Example | Confidence |
|---|---|---|
| IPv4 Address | `185.220.101.47` | 75% |
| Domain | `malicious-update.xyz` | 65% |
| SHA-256 Hash | `3f4a6b2c...` | 95% |
| MD5 Hash | `a1b2c3d4...` | 80% |
| Email | `attacker@proton.me` | 85% |
| URL | `http://c2.evil/upload` | 90% |

---

## 📁 Project Structure

```
incident-response-toolkit/
├── src/
│   └── ir_toolkit.py      # Core IR engine (collector, extractor, playbooks)
├── tests/
│   └── test_ir.py
├── playbooks/             # YAML playbook definitions (extensible)
├── evidence/              # Artefact output (git-ignored)
├── main.py
├── requirements.txt
└── README.md
```

---

## 🎓 Aligned Certifications

- **GIAC GCFE** (forensic examiner)
- **GIAC GCIH** (incident handler)
- **CompTIA CySA+**
- **EC-Council CHFI**
