# CyberSentinel — Intelligent Cyber Threat Detection System

> **ICTDS v3.0** · Machine Learning · Flask · SocketIO · "Clinical Clarity" UI

An enterprise-grade cybersecurity platform that detects and classifies malicious network activity using an explainable ML ensemble. It features real-time traffic monitoring, deep-packet analysis, and professional forensic reporting with a high-contrast **"Clinical Clarity"** light-mode aesthetic designed for security operations centers.

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| 🤖 **Explainable ML** | XGBoost + Calibrated Classifier with SHAP feature importance |
| 📡 **Live Monitor** | Real-time packet simulation and classification via SocketIO |
| 📊 **Real Dataset Support** | Natively trains on CIC-IDS 2017 (~97% accuracy) |
| 🧪 **Synthetic Fallback** | Auto-generates high-fidelity traffic data if no dataset found |
| 🔐 **Admin RBAC** | Dedicated administrative panel for user and log management |
| 📄 **Forensic Reports** | Professional PDF export for incident documentation (ReportLab) |
| 📈 **Interactive Dash** | Real-time telemetry, 24h threat timeline, and classification mix |
| 📋 **Security Audit** | Advanced filterable audit trail with CSV export and responsive layout |
| 🎨 **Clinical Clarity UI** | Professional light-mode aesthetic using Inter and JetBrains Mono |

---

## 💻 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.10+, Flask 3.x, Flask-SocketIO |
| **Machine Learning** | XGBoost, SHAP, scikit-learn, pandas, NumPy |
| **Forensics** | ReportLab (PDF), Scapy (PCAP Processing) |
| **Database** | SQLite3 (Persistent storage) |
| **Frontend** | HTML5, CSS3 (Vanilla), JS (ES6+), Chart.js 4 |
| **Typography** | Inter (UI), JetBrains Mono (Data) |

---

## 🚀 Installation & Setup

### Prerequisites

- Python **3.8** or higher
- `pip` (Python package installer)

### Steps

**1. Clone or navigate to the project directory**

```bash
cd "d:\ictds - Copy"
```

**2. Create and activate a virtual environment**

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Run the application**

```bash
python app.py
```

Or use the provided Windows batch script:

```cmd
Run.bat
```

**5. Open in your browser**

```
http://localhost:5001
```

> **Demo credentials:** `admin` / `admin123`

---

## 📊 Dataset Configuration (CIC-IDS 2017)

By default the system trains on synthetic data (~79% accuracy). For production-grade accuracy (~97%), use the real **CIC-IDS 2017** dataset.

1. Download from [UNB CIC-IDS 2017](https://www.unb.ca/cic/datasets/ids-2017.html) → click **MachineLearningCVE**
2. Create the target folder:
   ```
   data\cicids\
   ```
3. Copy all downloaded `.csv` files into `data\cicids\`
4. Delete the existing model to force a retrain:
   ```bash
   del model\model.pkl
   ```
5. Restart the app — it auto-detects the dataset, trains both models, and saves `model.pkl`

The dashboard status will indicate **CIC-IDS 2017 Dataset · ~97% Accuracy** when initialized.

---

## 🗺️ Application Routes

### Pages

| Route | Method | Description |
|---|---|---|
| `/` | GET | Redirects to dashboard or login |
| `/login` | GET, POST | Terminal-style secure login |
| `/register` | GET, POST | New analyst registration with password strength |
| `/logout` | GET | Clears session |
| `/dashboard` | GET | Security overview — timeline, top threats, activity feed |
| `/analyse` | GET, POST | Upload CSV and run threat classification |
| `/threats` | GET | Dedicated threat intelligence report with pagination |
| `/logs` | GET | Filterable detection audit trail with CSV export |
| `/monitor` | GET | Real-time streaming packet sniffer (Live Monitor) |
| `/admin` | GET | Administrative dashboard for RBAC and log maintenance |
| `/export_pdf` | GET | Generates forensic incident report in PDF format |
| `/export_logs` | GET | Downloads filter-refined logs as CSV |

### REST API Endpoints

| Route | Description | Response |
|---|---|---|
| `/api/stats` | Last 200 detection records | `[{prediction, severity, timestamp}]` |
| `/api/threat_timeline` | Hourly threat/safe counts for last 24h | `[{hour, threats, safe}]` |
| `/api/severity_dist` | Severity distribution for current user | `[{severity, cnt}]` |
| `/api/attack_types` | Top attack types (threats only) | `[{prediction, cnt}]` |
| `/api/model_status` | Current model & dataset info | `{dataset_type, accuracy_label, …}` |

---

## 🧠 ML Classification Labels

| Class | Description | Severity |
|---|---|---|
| `normal` | Benign traffic | None / Low |
| `dos` | Denial-of-Service (Hulk, GoldenEye, Slowloris, DDoS…) | High |
| `probe` | Port scanning / reconnaissance | Medium |
| `r2l` | Remote-to-Local (Brute Force, XSS, SQL Injection, Web Attack…) | High |
| `u2r` | User-to-Root / Infiltration / Botnet | Critical |

---

## 📂 Project Structure

```text
ictds/
│
├── app.py                  # Flask application — all routes & API logic
├── requirements.txt        # Python dependencies
├── Run.bat                 # Windows one-click launcher
├── ictds.db                # SQLite database (auto-created on first run)
├── README.md               # This file
├── SKILL.md                # Frontend design specification
│
├── data/
│   └── cicids/             # Place CIC-IDS 2017 CSV files here
│
├── model/
│   ├── threat_model.py     # ThreatDetector class, training, prediction
│   └── model.pkl           # Serialized ensemble model (auto-generated)
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Professional light-mode layout & sidebar
│   ├── login.html          # Clean authentication interface
│   ├── dashboard.html      # Real-time telemetry & security KPIs
│   ├── analyse.html        # Multi-step traffic classification pipeline
│   ├── threats.html        # Detailed threat intelligence report
│   ├── monitor.html        # Live SocketIO traffic stream (NEW)
│   ├── admin.html          # Administrative user management (NEW)
│   └── logs.html           # Advanced searchable detection audit trail
│
└── venv/                   # Python virtual environment (not committed)
```

---

## 🎨 UI Design System — "Clinical Clarity"

The frontend adheres to a high-contrast, professional light-mode design:

| Token | Value | Usage |
|---|---|---|
| `--bg` | `#F4F6FB` | Global background |
| `--accent` | `#0066FF` | Corporate Blue — primary actions |
| `--danger` | `#E8003D` | Alert Red — threat detection |
| `--safe` | `#00875A` | Success Green — clean traffic |
| `--text-primary`| `#0D1117` | High-contrast body text |
| **Font (Body)** | `Inter` | User interface and headings |
| **Font (Mono)** | `JetBrains Mono` | Forensic data and code views |

---

## 🔒 Security Notes

- Passwords are hashed with **SHA-256** before storage — never stored in plain text
- File uploads are validated for `.csv` extension before processing
- Flask session secret key should be changed to a cryptographically random value for production
- For production deployment, replace the built-in Flask server with **Gunicorn** or **uWSGI** behind **Nginx**

---

## 📦 requirements.txt

```text
flask>=3.0.0
pandas>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
```

---

## 📋 Changelog

### v3.0 — May 2026
- 🎨 **Redesigned** complete UI to "Clinical Clarity" Light Mode for professional SOC environments.
- ✨ **Added** Live Monitor page using SocketIO for real-time traffic visualization.
- ✨ **Added** Forensic PDF Exporting using ReportLab for official incident reporting.
- ✨ **Added** Administrative Panel with RBAC (Role-Based Access Control).
- ✨ **Added** SHAP integration for ML feature importance and model explainability.
- ✨ **Added** XGBoost optimized engine replacing standard Gradient Boosting.
- 📱 **Refined** Mobile responsiveness across all data-heavy components.
- 🔧 **Improved** Database transaction stability with explicit commits.

### v2.0 — May 2026
- ✅ **Fixed** threat count mismatch between dashboard and detection logs.
- ✨ **Added** Threat Intelligence page with pagination and severity heatmap.

### v1.0 — April 2026
- Initial release with dashboard, analyse, logs, login, register

---

## 👥 Team

| Name | Role |
|---|---|
| Saranya A. | Full-Stack Development & ML Integration |
| Uma M. | Machine Learning & Data Engineering |
| Thanzim P. | Frontend Design & Testing |

---

## 📄 License

This project is developed for academic purposes as part of an Information Security / Cybersecurity coursework submission.
