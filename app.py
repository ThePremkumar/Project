"""
Intelligent Cyber Threat Detection System
Flask Backend — app.py
Team: Saranya A., Uma M., Thanzim P.
"""
import os, sys, json, hashlib, io
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, send_file)
import sqlite3, pandas as pd, numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "model"))
from threat_model import (get_or_train, make_synthetic,
                           load_cicids, SEVERITY, COLOR,
                           CICIDS_DIR, MODEL_PATH)

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "ictds-secret-2024"
app.jinja_env.globals.update(enumerate=enumerate)
DB = os.path.join(os.path.dirname(__file__), "ictds.db")

# Load / train model at startup
detector = get_or_train()

# ── Database ───────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id  INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS logs (
            log_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER,
            filename     TEXT,
            traffic_data TEXT,
            prediction   TEXT,
            confidence   REAL,
            severity     TEXT,
            is_threat    INTEGER DEFAULT 0,
            timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );
        """)
    # seed demo user
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username, password) VALUES (?,?)",
                       ("admin", _hash("admin123")))
    except Exception:
        pass

def _hash(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ── Auth helper ────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ── Helper: dataset status info ───────────────────────────────────────────
def get_model_status():
    """Returns a dict with current model/dataset info shown in templates."""
    cicids_files = []
    if os.path.isdir(CICIDS_DIR):
        cicids_files = [f for f in os.listdir(CICIDS_DIR) if f.lower().endswith(".csv")]

    return {
        "dataset_type":   detector.dataset_type,
        "is_cicids":      detector.dataset_type == "cicids",
        "cicids_files":   len(cicids_files),
        "cicids_dir":     os.path.abspath(CICIDS_DIR),
        "model_exists":   os.path.exists(MODEL_PATH),
        "accuracy_label": "~97%" if detector.dataset_type == "cicids" else "~79%",
    }

# ── Routes: Auth ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        uname = request.form.get("username", "").strip()
        pw    = request.form.get("password", "")
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM users WHERE username=? AND password=?",
                (uname, _hash(pw))
            ).fetchone()
        if row:
            session["user_id"]  = row["user_id"]
            session["username"] = row["username"]
            flash(f"Welcome back, {row['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = request.form.get("username", "").strip()
        pw    = request.form.get("password", "")
        if len(uname) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return render_template("register.html")
        try:
            with get_db() as db:
                db.execute("INSERT INTO users (username, password) VALUES (?,?)",
                           (uname, _hash(pw)))
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ── Routes: Dashboard ──────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        total   = db.execute("SELECT COUNT(*) FROM logs WHERE user_id=?",
                             (session["user_id"],)).fetchone()[0]
        threats = db.execute("SELECT COUNT(*) FROM logs WHERE user_id=? AND is_threat=1",
                             (session["user_id"],)).fetchone()[0]
        recent  = db.execute(
            "SELECT * FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 10",
            (session["user_id"],)
        ).fetchall()
        by_type = db.execute(
            "SELECT prediction, COUNT(*) as cnt FROM logs WHERE user_id=? GROUP BY prediction",
            (session["user_id"],)
        ).fetchall()

    safe       = total - threats
    threat_pct = round(threats / total * 100, 1) if total else 0

    chart_labels = [r["prediction"] for r in by_type]
    chart_values = [r["cnt"]        for r in by_type]
    chart_colors = [
        "#00E5A0" if l == "normal" else
        "#FF4D6D" if l in ("dos","r2l","u2r") else "#FFAA00"
        for l in chart_labels
    ]

    return render_template("dashboard.html",
        total=total, threats=threats, safe=safe, threat_pct=threat_pct,
        recent=recent,
        chart_labels=json.dumps(chart_labels),
        chart_values=json.dumps(chart_values),
        chart_colors=json.dumps(chart_colors),
        model_status=get_model_status(),
    )

# ── Routes: Analyse / Upload ───────────────────────────────────────────────
@app.route("/analyse", methods=["GET", "POST"])
@login_required
def analyse():
    results  = None
    filename = None
    summary  = {}

    if request.method == "POST":
        f = request.files.get("csv_file")
        if not f or not f.filename.endswith(".csv"):
            flash("Please upload a valid CSV file.", "danger")
            return render_template("analyse.html", model_status=get_model_status())

        filename = f.filename
        try:
            df = pd.read_csv(f)
            # clean column names — handles CIC-IDS spaces + capitals automatically
            df.columns = (
                df.columns.str.strip()
                          .str.lower()
                          .str.replace(" ", "_")
            )

            # drop any existing label column so it doesn't confuse the model
            df = df.drop(columns=["label"," label"], errors="ignore")

            result_df = detector.predict_df(df)

            # save to DB
            safe_cols = ["protocol_type","service","flag","src_bytes","dst_bytes"]
            with get_db() as db:
                for _, row in result_df.iterrows():
                    traffic_snapshot = {}
                    if all(c in row for c in safe_cols):
                        traffic_snapshot = {c: row[c] for c in safe_cols}
                    db.execute(
                        """INSERT INTO logs
                           (user_id,filename,traffic_data,prediction,
                            confidence,severity,is_threat,timestamp)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (session["user_id"], filename,
                         json.dumps(traffic_snapshot),
                         row["prediction"],
                         float(row["confidence"]),
                         row["severity"],
                         int(row["is_threat"]),
                         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    )

            results    = result_df[
                ["prediction","confidence","severity","badge_color","is_threat"]
            ].to_dict("records")
            total_rows = len(result_df)
            threat_rows= int(result_df["is_threat"].sum())
            summary = {
                "total":      total_rows,
                "threats":    threat_rows,
                "safe":       total_rows - threat_rows,
                "threat_pct": round(threat_rows / total_rows * 100, 1) if total_rows else 0,
                "by_type":    result_df["prediction"].value_counts().to_dict(),
            }
            flash(
                f"Analysis complete — {threat_rows} threat(s) detected "
                f"in {total_rows} records.",
                "success"
            )

        except Exception as e:
            flash(f"Error processing file: {e}", "danger")

    return render_template("analyse.html",
        results=results, filename=filename, summary=summary,
        model_status=get_model_status()
    )

# ── Routes: Logs ───────────────────────────────────────────────────────────
@app.route("/logs")
@login_required
def logs():
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 200",
            (session["user_id"],)
        ).fetchall()
    return render_template("logs.html", logs=rows, model_status=get_model_status())

# ── Routes: API ────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    with get_db() as db:
        rows = db.execute(
            "SELECT prediction, severity, timestamp FROM logs "
            "WHERE user_id=? ORDER BY timestamp DESC LIMIT 100",
            (session["user_id"],)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

# ── Routes: Demo ───────────────────────────────────────────────────────────
@app.route("/demo")
@login_required
def demo():
    df        = make_synthetic(20).drop(columns=["label"], errors="ignore")
    result_df = detector.predict_df(df)
    with get_db() as db:
        for _, row in result_df.iterrows():
            db.execute(
                """INSERT INTO logs
                   (user_id,filename,traffic_data,prediction,
                    confidence,severity,is_threat,timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (session["user_id"], "demo_run.csv", "{}",
                 row["prediction"], float(row["confidence"]),
                 row["severity"], int(row["is_threat"]),
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
    flash("Demo analysis complete — 20 synthetic packets analysed.", "info")
    return redirect(url_for("dashboard"))

# ── Routes: Sample CSV download ────────────────────────────────────────────
@app.route("/sample_csv")
@login_required
def sample_csv():
    """
    If CIC-IDS data is present, export a real sample from it.
    Otherwise export synthetic data.
    """
    import os as _os
    cicids_files = []
    if _os.path.isdir(CICIDS_DIR):
        cicids_files = [f for f in _os.listdir(CICIDS_DIR) if f.lower().endswith(".csv")]

    if cicids_files:
        # grab first 10 rows from the first CIC-IDS file as sample
        path = _os.path.join(CICIDS_DIR, sorted(cicids_files)[0])
        sample = pd.read_csv(path, nrows=10, low_memory=False)
        sample.columns = sample.columns.str.strip().str.lower().str.replace(" ","_")
        sample = sample.drop(columns=["label"," label"], errors="ignore")
    else:
        sample = make_synthetic(10).drop(columns=["label"])

    buf = io.StringIO()
    sample.to_csv(buf, index=False)
    buf.seek(0)
    return send_file(
        io.BytesIO(buf.read().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="sample_traffic.csv"
    )

# ── Routes: Retrain model ──────────────────────────────────────────────────
@app.route("/retrain", methods=["POST"])
@login_required
def retrain():
    """
    Delete saved model and retrain.
    If CIC-IDS files are present → trains on real data.
    Otherwise → trains on synthetic data.
    """
    global detector
    try:
        # delete old model so get_or_train retrains fresh
        if os.path.exists(MODEL_PATH):
            os.remove(MODEL_PATH)
        detector = get_or_train()
        dtype = detector.dataset_type.upper()
        flash(f"Model retrained successfully on {dtype} data!", "success")
    except Exception as e:
        flash(f"Retrain failed: {e}", "danger")
    return redirect(url_for("dashboard"))

# ── Routes: Dataset status (JSON) ─────────────────────────────────────────
@app.route("/api/model_status")
@login_required
def api_model_status():
    return jsonify(get_model_status())

# ── Boot ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5001)