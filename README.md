# CyberSentinel — Intelligent Cyber Threat Detection System

> **ICTDS v2.0** · Machine Learning · Flask · SQLite · CIC-IDS 2017 · "Void Terminal" UI

An end-to-end web-based cybersecurity platform that detects and classifies malicious network activity using a dual-model machine learning ensemble. Users upload network traffic logs (CSV), receive instant threat classifications with severity scoring, and monitor security trends through a real-time interactive dashboard with a premium **"Void Terminal"** dark aesthetic.

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| 🤖 **ML Ensemble** | Random Forest + Gradient Boosting voting classifier |
| 📊 **Real Dataset Support** | Natively trains on CIC-IDS 2017 (~97% accuracy) |
| 🧪 **Synthetic Fallback** | Auto-generates NSL-KDD style data if no dataset found |
| 🔐 **User Authentication** | Secure login & registration with SHA-256 hashing |
| 📁 **CSV Upload & Analysis** | Drag-and-drop file upload with ML-based real-time classification |
| 📈 **Live Dashboard** | 24-hour timeline chart, metric cards, top threats ranking, activity feed |
| ⚠️ **Threat Intelligence Page** | Dedicated threat report with type breakdown, severity heatmap & pagination |
| 📋 **Detection Logs** | 4-filter searchable audit trail (type, status, severity, text) with CSV export |
| 🔄 **Model Retraining** | One-click retrain from the dashboard |
| 📥 **Sample CSV Download** | Pre-built sample from real or synthetic data |
| 📡 **REST API** | JSON endpoints for stats, timeline, severity, attack types |
| 🎨 **"Void Terminal" UI** | Space Mono + Outfit fonts, neon teal/coral palette, scanline texture, animated sidebar |

---

## 💻 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.8+, Flask 3.x |
| **Machine Learning** | scikit-learn (Random Forest, Gradient Boosting), pandas, NumPy |
| **Database** | SQLite (via Python `sqlite3`) |
| **Frontend** | HTML5, Vanilla CSS3, JavaScript (ES6+), Bootstrap 5, Chart.js 4 |
| **Fonts & Icons** | Google Fonts (Space Mono, Outfit), Font Awesome 6 |
| **Model Storage** | Pickle (`.pkl`) |

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

The dashboard subtitle will show **CIC-IDS 2017 Dataset · ~97% Accuracy** once loaded.

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
| `/demo` | GET | Analyses 20 synthetic packets instantly |
| `/sample_csv` | GET | Downloads a sample input CSV |
| `/retrain` | POST | Deletes model and retrains from scratch |
| `/export_logs` | GET | Downloads all user logs as timestamped CSV |

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
│   ├── base.html           # Shared layout — sidebar, nav, design system
│   ├── login.html          # Terminal-window login page
│   ├── register.html       # Registration with password strength meter
│   ├── dashboard.html      # Timeline, top threats, activity feed, metrics
│   ├── analyse.html        # CSV upload & pipeline results
│   ├── threats.html        # Dedicated threat intelligence report (NEW)
│   └── logs.html           # Filterable detection log with export
│
└── venv/                   # Python virtual environment (not committed)
```

---

## 🎨 UI Design System — "Void Terminal"

The frontend follows a **neo-brutalist terminal aesthetic** defined in `SKILL.md`:

| Token | Value | Usage |
|---|---|---|
| `--bg` | `#07090F` | Page background |
| `--accent` | `#00FFD1` | Electric teal — primary actions |
| `--danger` | `#FF3366` | Coral red — threats & alerts |
| `--warn` | `#FF9500` | Amber — medium severity |
| `--safe` | `#00E5A0` | Green — safe traffic |
| **Font (Display)** | `Space Mono` | Numbers, labels, mono data |
| **Font (Body)** | `Outfit` | UI text, headings |
| **Effect** | Scanline texture | CSS repeating-linear-gradient overlay |
| **Effect** | Animated grid | CSS background drift animation |
| **Effect** | Glowing blobs | Blurred radial gradients at corners |

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

### v2.0 — May 2026
- ✅ **Fixed** threat count mismatch between dashboard and detection logs (moved to server-side SQL COUNT)
- ✨ **Added** Threat Intelligence page (`/threats`) with pagination, attack type bars, severity breakdown
- ✨ **Added** 24-hour threat timeline chart (live from `/api/threat_timeline`)
- ✨ **Added** Top Threats ranking panel on dashboard
- ✨ **Added** Live activity feed on dashboard
- ✨ **Added** Threat alert banner when threats detected
- ✨ **Added** 4 new REST API endpoints (`threat_timeline`, `severity_dist`, `attack_types`, `recent_critical`)
- ✨ **Added** "Threats" navigation item with live badge count in sidebar
- 🎨 **Redesigned** all pages with "Void Terminal" aesthetic (Space Mono, Outfit, neon palette, scanlines)
- 🎨 **Redesigned** login/register with terminal window chrome + cursor blink animation
- 🎨 **Redesigned** analyse page with 4-step pipeline visualization

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
