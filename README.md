<div align="center">

# 🛡️ WinHardener

### Automated CIS Compliance & Hardening for Windows 11 — Built for Air-Gapped & OT Environments

<p>
  <img src="https://img.shields.io/badge/CIS_Benchmark-v5.0.0-2ea44f?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Controls-57-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Remediation-%3C10s-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Air--Gapped-Yes-critical?style=for-the-badge" />
</p>

<p>
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black" />
  <img src="https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white" />
  <img src="https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows_11-0078D6?style=flat-square&logo=windows&logoColor=white" />
</p>

*Built during an OT Security & Industrial Networking internship at **Rockwell Automation***

[Overview](#-overview) • [Features](#-features) • [Screenshots](#-screenshots) • [Architecture](#️-architecture) • [Getting Started](#-getting-started) • [Compliance Coverage](#-what-gets-audited) • [Roadmap](#️-roadmap)

</div>

<br />

## 📖 Overview

Manually auditing a Windows endpoint against a CIS Benchmark is slow, repetitive, and easy to get wrong — and in **OT/ICS environments**, where HMIs, historians, and engineering workstations are often standalone and air-gapped, that manual process doesn't scale at all.

**WinHardener** is a self-contained Flask application that scans a Windows 11 machine against **57 controls from the CIS Microsoft Windows 11 Stand-alone Benchmark v5.0.0**, shows a live compliance score, and remediates failing controls — individually or in bulk — in under 10 seconds. No internet connection, external services, or CDNs required at runtime, so it runs cleanly inside isolated industrial networks.

<br />

## ✨ Features

| | |
|---|---|
| 📊 **Live Compliance Score** | Real-time pass/fail/error breakdown across all 57 controls |
| ⚡ **One-Click Remediation** | Apply All / Reset All per category, or act on a single control |
| 🔐 **Role-Based Access** | Admin (full read/write) vs. Guest (read-only audit) |
| 📄 **PDF Compliance Reports** | Exportable audit trail with CIS ID, required vs. current value, and pass/fail status |
| 🧾 **Activity Logging** | Every policy change is timestamped and recorded to JSON |
| 🔌 **Air-Gap Ready** | Zero external dependencies at runtime — safe for isolated OT/SCADA networks |
| 🎯 **Benchmark-Traceable** | Every control maps to a specific CIS v5.0.0 recommendation ID |

<br />

## 📸 Screenshots

**Login — Role-Based Access Control**
<br />
<img src="https://github.com/Niranjan20061907/WinHardener/raw/main/docs/screenshots/login.PNG" width="700" alt="Login page with admin and guest roles" />

*Admins can apply and reset policies; guests get read-only audit and export access.*

**System Hardening Dashboard**
<br />
<img src="https://github.com/Niranjan20061907/WinHardener/raw/main/docs/screenshots/dashboard.PNG" width="700" alt="Dashboard showing live compliance score" />

*Live compliance score across all 57 controls, with one-click Apply/Reset per category and PDF export.*

**Compliance Report (PDF Export)**
<br />
<img src="https://github.com/Niranjan20061907/WinHardener/raw/main/docs/screenshots/report.PNG" width="700" alt="Exported PDF compliance report" />

*Paginated audit report with an executive summary and a full control-by-control breakdown — built for tracking compliance progress and sharing with stakeholders.*

<br />

## 🏗️ Architecture

```
WinHardener/
├── app.py                  # Flask application, routing, and access control
├── policies.py             # CIS Benchmark schema, target values, and thresholds
├── policy_executor.py      # Core engine — maps Python rules to Windows OS commands
├── requirements.txt        # Python dependencies
├── data/                   # Local storage for scan results and audit logs
│   ├── activity_log.json
│   └── custom_values.json
├── static/                 # Frontend assets
│   ├── style.css
│   └── dashboard.js
└── templates/              # HTML templates
    ├── dashboard.html
    ├── logs.html
    └── login.html
```

**Under the hood:** policy state is read and written via `subprocess` calls to `secedit`, `reg.exe`, and `sc.exe`, with direct Windows Registry access through `winreg` — no third-party Windows automation libraries, keeping the tool dependency-free and safe to run on locked-down endpoints.

<br />

## 🚀 Getting Started

### Prerequisites
- Windows 11 (required — reads the Windows Registry and Local/Group Policy)
- Python 3.10+
- Administrator privileges (required for registry writes and policy application)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Niranjan20061907/WinHardener.git
cd WinHardener

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the application (as Administrator)
python app.py
```

### Access the Dashboard

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

Sign in as **admin** for full audit + remediation access, or **Continue as Guest** for read-only auditing.

<br />

## 🔍 What Gets Audited

| Category | Controls | What It Checks |
|---|:---:|---|
| **Password Policies** | 7 | Length, history, max/min age, complexity, reversible encryption |
| **Account Lockout Policies** | 4 | Lockout threshold, duration, observation window, admin lockout |
| **Local Policy** | 2 | User rights assignment (log on locally, back up files/directories) |
| **System Services** | 44 | Startup state for 44 Windows services per CIS guidance |
| **Total** | **57** | |

Each control resolves to one of three states:

- ✅ **PASS** — meets the CIS requirement
- ❌ **FAIL** — does not meet the requirement (remediation available)
- ⚠️ **ERROR** — could not be read (permissions or OS edition mismatch)

<br />

## 🏭 Why This Matters for OT/ICS

Most Windows hardening tools assume an internet-connected, domain-joined machine. WinHardener is built for the opposite case:

- **Air-gap compatible** — no internet, no cloud dependencies, no telemetry
- **Standalone-endpoint focus** — targets HMI/SCADA workstations, historian nodes, and engineering stations
- **Non-disruptive auditing** — guest mode scans without changing anything
- **Operator-controlled remediation** — Apply/Reset actions are explicit and per-category, never automatic

<br />

## 📋 Benchmark Reference

This tool implements controls from the **CIS Microsoft Windows 11 Stand-alone Benchmark, Version 5.0.0** (Center for Internet Security — [cisecurity.org](https://www.cisecurity.org)). Every control in `policies.py` references its exact CIS recommendation ID (e.g. `1.1.1`, `2.3.1`) for full traceability.

<br />

## 🗺️ Roadmap

- [ ] Audit Policy controls (Event Log, Windows Audit settings)
- [ ] SMBv1 / NetBIOS detection — closes a key OT attack surface (e.g. WannaCry-class exploits)
- [ ] Scheduled scans with email/webhook alerting
- [ ] Scan history and compliance trend charting
- [ ] Docker support for Windows Server deployments

<br />

## 👤 Author

**Niranjan Krishnarajarajan**
B.Tech Computer Science, NIT Rourkela
[LinkedIn](https://www.linkedin.com/in/niranjan-krishnarajarajan-768625332/) · [GitHub](https://github.com/Niranjan20061907)

<br />

## ⚖️ Disclaimer

This tool modifies Windows Registry and Group/Local Policy settings. Always test in a non-production environment before applying to operational systems. The author and Rockwell Automation are not responsible for system instability resulting from applying CIS hardening controls to production OT endpoints.

<br />

<div align="center">

*CIS Windows 11 Benchmark v5.0.0 · © 2026 Niranjan Krishnarajarajan*

</div>
