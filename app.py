"""
Intelligent Cyber Threat Detection System
Flask Backend — app.py
Team: Saranya A., Uma M., Thanzim P.
"""
import os, sys, json, hashlib, io, csv
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, send_file, Response)
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
    uid = session["user_id"]
    with get_db() as db:
        total   = db.execute("SELECT COUNT(*) FROM logs WHERE user_id=?", (uid,)).fetchone()[0]
        threats = db.execute("SELECT COUNT(*) FROM logs WHERE user_id=? AND is_threat=1", (uid,)).fetchone()[0]
        recent  = db.execute(
            "SELECT * FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 10", (uid,)
        ).fetchall()
        by_type = db.execute(
            "SELECT prediction, COUNT(*) as cnt FROM logs WHERE user_id=? GROUP BY prediction", (uid,)
        ).fetchall()
        # Top threats (non-normal only)
        top_threats = db.execute(
            "SELECT prediction, COUNT(*) as cnt FROM logs WHERE user_id=? AND is_threat=1 GROUP BY prediction ORDER BY cnt DESC LIMIT 5",
            (uid,)
        ).fetchall()

    safe       = total - threats
    threat_pct = round(threats / total * 100, 1) if total else 0

    chart_labels = [r["prediction"] for r in by_type]
    chart_values = [r["cnt"]        for r in by_type]
    chart_colors = [
        "#00FFD1" if l == "normal" else
        "#FF3366" if l in ("dos","r2l","u2r") else "#FF9500"
        for l in chart_labels
    ]

    return render_template("dashboard.html",
        total=total, threats=threats, safe=safe, threat_pct=threat_pct,
        recent=recent, top_threats=top_threats,
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
            df.columns = (
                df.columns.str.strip()
                          .str.lower()
                          .str.replace(" ", "_")
            )
            df = df.drop(columns=["label"," label"], errors="ignore")
            result_df = detector.predict_df(df)

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
    uid = session["user_id"]
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 200", (uid,)
        ).fetchall()
        total_logs   = db.execute("SELECT COUNT(*) FROM logs WHERE user_id=?", (uid,)).fetchone()[0]
        threat_count = db.execute("SELECT COUNT(*) FROM logs WHERE user_id=? AND is_threat=1", (uid,)).fetchone()[0]
        safe_count   = total_logs - threat_count
    logs_stats = {
        "total":      total_logs,
        "threats":    threat_count,
        "safe":       safe_count,
        "threat_pct": round(threat_count / total_logs * 100, 1) if total_logs else 0,
    }
    return render_template("logs.html", logs=rows, logs_stats=logs_stats, model_status=get_model_status())

# ── Routes: Threats page ───────────────────────────────────────────────────
@app.route("/threats")
@login_required
def threats():
    """Dedicated threats-only view with pagination."""
    uid  = session["user_id"]
    page = max(1, int(request.args.get("page", 1)))
    per  = 50
    offset = (page - 1) * per
    with get_db() as db:
        total_threats = db.execute(
            "SELECT COUNT(*) FROM logs WHERE user_id=? AND is_threat=1", (uid,)
        ).fetchone()[0]
        rows = db.execute(
            "SELECT * FROM logs WHERE user_id=? AND is_threat=1 ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (uid, per, offset)
        ).fetchall()
        by_type = db.execute(
            "SELECT prediction, COUNT(*) as cnt FROM logs WHERE user_id=? AND is_threat=1 GROUP BY prediction ORDER BY cnt DESC",
            (uid,)
        ).fetchall()
        by_severity = db.execute(
            "SELECT severity, COUNT(*) as cnt FROM logs WHERE user_id=? AND is_threat=1 GROUP BY severity ORDER BY cnt DESC",
            (uid,)
        ).fetchall()
    pages = max(1, (total_threats + per - 1) // per)
    return render_template("threats.html",
        threats=rows, total_threats=total_threats,
        by_type=by_type, by_severity=by_severity,
        page=page, pages=pages, per=per,
        model_status=get_model_status()
    )

# ── Routes: API ────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    uid = session["user_id"]
    with get_db() as db:
        rows = db.execute(
            "SELECT prediction, severity, timestamp FROM logs "
            "WHERE user_id=? ORDER BY timestamp DESC LIMIT 200",
            (uid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/threat_timeline")
@login_required
def api_threat_timeline():
    """Returns hourly threat/safe counts for the last 24 hours."""
    uid = session["user_id"]
    with get_db() as db:
        rows = db.execute(
            "SELECT timestamp, is_threat FROM logs WHERE user_id=? "
            "ORDER BY timestamp DESC LIMIT 5000",
            (uid,)
        ).fetchall()

    buckets = defaultdict(lambda: {"threats": 0, "safe": 0})
    now = datetime.now()
    for r in rows:
        try:
            ts = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S")
            diff = (now - ts).total_seconds() / 3600
            if diff <= 24:
                hour_key = ts.strftime("%H:00")
                if r["is_threat"]:
                    buckets[hour_key]["threats"] += 1
                else:
                    buckets[hour_key]["safe"] += 1
        except Exception:
            pass

    # Build 24-slot timeline
    slots = []
    for i in range(23, -1, -1):
        t = (now - timedelta(hours=i))
        key = t.strftime("%H:00")
        b = buckets.get(key, {"threats": 0, "safe": 0})
        slots.append({"hour": key, "threats": b["threats"], "safe": b["safe"]})
    return jsonify(slots)

@app.route("/api/severity_dist")
@login_required
def api_severity_dist():
    """Severity distribution for current user."""
    uid = session["user_id"]
    with get_db() as db:
        rows = db.execute(
            "SELECT severity, COUNT(*) as cnt FROM logs WHERE user_id=? GROUP BY severity",
            (uid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/attack_types")
@login_required
def api_attack_types():
    """Top attack types for current user."""
    uid = session["user_id"]
    with get_db() as db:
        rows = db.execute(
            "SELECT prediction, COUNT(*) as cnt FROM logs WHERE user_id=? "
            "AND is_threat=1 GROUP BY prediction ORDER BY cnt DESC",
            (uid,)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/recent_critical")
@login_required
def api_recent_critical():
    """Most recent critical/high severity threats."""
    uid = session["user_id"]
    with get_db() as db:
        rows = db.execute(
            "SELECT prediction, severity, confidence, timestamp, filename FROM logs "
            "WHERE user_id=? AND is_threat=1 AND severity IN ('Critical','High') "
            "ORDER BY timestamp DESC LIMIT 5",
            (uid,)
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
    import os as _os
    cicids_files = []
    if _os.path.isdir(CICIDS_DIR):
        cicids_files = [f for f in _os.listdir(CICIDS_DIR) if f.lower().endswith(".csv")]

    if cicids_files:
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
    global detector
    try:
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

# ── Routes: Export logs as CSV ─────────────────────────────────────────────
@app.route("/export_logs")
@login_required
def export_logs():
    with get_db() as db:
        rows = db.execute(
            "SELECT log_id,filename,prediction,confidence,severity,is_threat,timestamp "
            "FROM logs WHERE user_id=? ORDER BY timestamp DESC",
            (session["user_id"],)
        ).fetchall()

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["ID","Filename","Prediction","Confidence","Severity","Is_Threat","Timestamp"])
        yield buf.getvalue(); buf.seek(0); buf.truncate()
        for row in rows:
            writer.writerow(list(row))
            yield buf.getvalue(); buf.seek(0); buf.truncate()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ictds_logs_{ts}.csv"}
    )

# ── Boot ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5001)