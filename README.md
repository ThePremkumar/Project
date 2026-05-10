# CyberSentinel — Intelligent Cyber Threat Detection System

> **ICTDS v2.0** · Machine Learning · Flask · SQLite · CIC-IDS 2017

An end-to-end web-based cybersecurity platform that detects and classifies malicious network activity using a dual-model machine learning ensemble. Users can upload network traffic logs (CSV), receive instant threat classifications, and monitor security trends through an interactive dark-themed dashboard.

---

## 🌟 Key Features

| Feature | Description |
|---|---|
| 🤖 **ML Ensemble** | Random Forest + Gradient Boosting voting classifier |
| 📊 **Real Dataset Support** | Natively trains on CIC-IDS 2017 (~97% accuracy) |
| 🧪 **Synthetic Fallback** | Auto-generates NSL-KDD style data if no dataset found |
| 🔐 **User Authentication** | Secure login & registration with SHA-256 hashing |
| 📁 **CSV Upload & Analysis** | Drag-and-drop file upload with real-time classification |
| 📈 **Live Dashboard** | Metric cards, bar chart, doughnut chart, recent detections table |
| 📋 **Detection Logs** | Filterable, searchable audit trail with CSV export |
| 🔄 **Model Retraining** | One-click retrain from the dashboard |
| 📥 **Sample CSV Download** | Pre-built sample from real or synthetic data |
| 🎨 **Premium Dark UI** | Glassmorphism, animated sidebar, Inter font, micro-animations |

---

## 💻 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.8+, Flask 3.x |
| **Machine Learning** | scikit-learn (Random Forest, Gradient Boosting), pandas, NumPy |
| **Database** | SQLite (via Python `sqlite3`) |
| **Frontend** | HTML5, CSS3 (Vanilla), JavaScript, Bootstrap 5, Chart.js |
| **Fonts & Icons** | Google Fonts (Inter), Font Awesome 6 |
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

| Route | Method | Description |
|---|---|---|
| `/` | GET | Redirects to dashboard or login |
| `/login` | GET, POST | User login |
| `/register` | GET, POST | New user registration |
| `/logout` | GET | Clears session |
| `/dashboard` | GET | Security overview, charts, recent detections |
| `/analyse` | GET, POST | Upload CSV and run threat classification |
| `/logs` | GET | Paginated detection audit trail |
| `/demo` | GET | Analyses 20 synthetic packets instantly |
| `/sample_csv` | GET | Downloads a sample input CSV |
| `/retrain` | POST | Deletes model and retrains from scratch |
| `/export_logs` | GET | Downloads all user logs as timestamped CSV |
| `/api/stats` | GET | JSON: last 100 detection records |
| `/api/model_status` | GET | JSON: current model/dataset info |

---

## 🧠 ML Classification Labels

| Class | Description | Severity |
|---|---|---|
| `normal` | Benign traffic | None |
| `dos` | Denial-of-Service (Hulk, GoldenEye, Slowloris, DDoS…) | High |
| `probe` | Port scanning / reconnaissance | Medium |
| `r2l` | Remote-to-Local (Brute Force, XSS, SQL Injection, Web Attack…) | High |
| `u2r` | User-to-Root / Infiltration / Botnet | Critical |

---

## 📂 Project Structure

```text
ictds/
│
├── app.py                  # Flask application — all routes & logic
├── requirements.txt        # Python dependencies
├── Run.bat                 # Windows one-click launcher
├── ictds.db                # SQLite database (auto-created on first run)
├── README.md               # This file
├── SKILL.md                # Project specification document
│
├── data/
│   └── cicids/             # Place CIC-IDS 2017 CSV files here
│
├── model/
│   ├── threat_model.py     # ThreatDetector class, training, prediction
│   └── model.pkl           # Serialized ensemble model (auto-generated)
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Shared layout — sidebar, nav, flash messages
│   ├── login.html          # Glassmorphism login page
│   ├── register.html       # Registration with password strength meter
│   ├── dashboard.html      # Metrics, charts, recent detections
│   ├── analyse.html        # CSV upload & classification results
│   └── logs.html           # Filterable detection log with CSV export
│
└── venv/                   # Python virtual environment (not committed)
```

---

## 🔒 Security Notes

- Passwords are hashed with **SHA-256** before storage — never stored in plain text
- File uploads are validated for `.csv` extension before processing
- Flask session secret key should be changed to a random value for production
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

## 👥 Team

| Name | Role |
|---|---|
| Saranya A. | Full-Stack Development & ML Integration |
| Uma M. | Machine Learning & Data Engineering |
| Thanzim P. | Frontend Design & Testing |

---

## 📄 License

This project is developed for academic purposes as part of an Information Security / Cybersecurity coursework submission.
