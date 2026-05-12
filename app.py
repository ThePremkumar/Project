"""
Intelligent Cyber Threat Detection System
Flask Backend — app.py
Team: Saranya A., Uma M., Thanzim P.
"""
import os, sys, json, hashlib, io, csv, sqlite3
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, send_file, Response)
import os, pickle, numpy as np, pandas as pd
import bcrypt, smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, emit
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import io
import threading, time
from scapy.all import rdpcap, IP, TCP, UDP

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "model"))
from threat_model import (get_or_train, make_synthetic,
                           load_cicids, SEVERITY, COLOR,
                           CICIDS_DIR, MODEL_PATH)

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit
app.secret_key = os.environ.get("ICTDS_SECRET_KEY")
if not app.secret_key:
    import secrets
    app.secret_key = secrets.token_hex(16)
    print("WARNING: Using random secret key (fallback generated)")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    on_breach=lambda e: jsonify(error="RATE LIMIT EXCEEDED — RETRY LATER", retry_after=e.description),
)
csrf = CSRFProtect(app)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

app.jinja_env.globals.update(enumerate=enumerate)
DB = os.path.join(os.path.dirname(__file__), "ictds.db")

# Load / train model at startup
detector = get_or_train()

# ── Database ───────────────────────────────────────────────────────────────
# ── Globals ─────────────────────────────────────────────────────────────────
SNIFFER_ACTIVE = False
SNIFFER_THREAD = None

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS logs (
            log_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER,
            filename     TEXT,
            traffic_data TEXT,
            prediction   TEXT,
            confidence   REAL,
            severity     TEXT,
            is_threat    INTEGER DEFAULT 0,
            timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username, password, is_admin) VALUES (?,?,?)",
                       ("admin", _hash("admin123"), 1))
            db.commit()
    except Exception:
        pass

def _hash(pw):
    """Bcrypt hashing."""
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def _check_pw(pw, hashed):
    """Verify password with bcrypt and SHA-256 fallback migration."""
    # Bcrypt hashes usually start with $2
    if hashed.startswith('$2'):
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    
    # Legacy SHA-256 check (64 hex chars)
    if len(hashed) == 64:
        legacy_hash = hashlib.sha256(pw.encode()).hexdigest()
        return legacy_hash == hashed
    
    return False

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

# ── WebSocket Background Thread ──────────────────────────────────────────────
def background_stats_thread():
    """Emits live stats every 5 seconds to all connected clients."""
    while True:
        socketio.sleep(5)
        with app.app_context():
            try:
                with get_db() as db:
                    # Get global stats (sum across all users for system-wide view, 
                    # or filter by active sessions if needed. Prompt says "live stats")
                    total   = db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
                    threats = db.execute("SELECT COUNT(*) FROM logs WHERE is_threat=1").fetchone()[0]
                    latest  = db.execute("SELECT prediction, severity, timestamp FROM logs ORDER BY timestamp DESC LIMIT 1").fetchone()
                
                safe = total - threats
                threat_pct = round(threats / total * 100, 1) if total else 0
                
                stats = {
                    "total": total,
                    "threats": threats,
                    "safe": safe,
                    "threat_pct": threat_pct,
                    "latest_log": dict(latest) if latest else None
                }
                socketio.emit('live_stats', stats)
            except Exception as e:
                print(f"WS Error: {e}")

# ── Alerting System ────────────────────────────────────────────────────────
def send_security_alert(threat_summary):
    """Sends email alert if threat is detected."""
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = os.environ.get("SMTP_PORT", "587")
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    
    if not all([smtp_host, smtp_user, smtp_pass]):
        print("[alert] SMTP settings missing. Alert logged to console.")
        print(f"[alert] THREAT DETECTED: {threat_summary}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = smtp_user # Send to self for demo
        msg['Subject'] = f"🛡️ CyberSentinel ALERT: {threat_summary['threats']} Threats Detected"

        body = f"""
        CYBERSENTINEL v3.0 SECURITY ALERT
        =================================
        Status: CRITICAL THREATS IDENTIFIED
        File: {threat_summary['filename']}
        Total Records: {threat_summary['total']}
        Threat Count: {threat_summary['threats']}
        
        TOP THREAT TYPES:
        {threat_summary['by_type']}
        
        ACTION REQUIRED: Review logs immediately in the CyberSentinel Dashboard.
        """
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(smtp_host, int(smtp_port))
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        print("[alert] Security email sent successfully.")
    except Exception as e:
        print(f"[alert] Failed to send email: {e}")

# ── Packet Simulation Thread ────────────────────────────────────────────────
def packet_simulator():
    """Simulates real-time network traffic and classifies it."""
    global SNIFFER_ACTIVE
    while True:
        if SNIFFER_ACTIVE:
            try:
                # Generate random network flow
                protocols = ['TCP', 'UDP', 'ICMP']
                p = np.random.choice(protocols)
                
                # Synthetic feature vector (simplified for demo)
                # In a real app, we'd use 'scapy' to sniff real packets
                flow_data = {
                    'duration':  np.random.random() * 2,
                    'protocol':  p,
                    'service':   'http' if p=='TCP' else 'dns',
                    'flag':      'SF',
                    'src_bytes': np.random.randint(100, 5000),
                    'dst_bytes': np.random.randint(100, 5000),
                    'count':     np.random.randint(1, 10),
                    'srv_count': np.random.randint(1, 10),
                }
                
                # Get ML prediction
                with app.app_context():
                    # We use the detector to classify this simulated flow
                    # Note: detector expects a specific feature set, so we fill defaults
                    full_features = {f: 0 for f in detector.features}
                    for k,v in flow_data.items():
                        if k in full_features: full_features[k] = v
                    
                    df = pd.DataFrame([full_features])
                    pred = detector.model.predict(df)[0]
                    prob = np.max(detector.model.predict_proba(df)[0])
                    
                    prediction = detector.le.inverse_transform([pred])[0]
                    is_threat = 1 if prediction != 'normal' else 0
                    severity = "High" if is_threat else "Normal"
                    
                    # Log to DB (Simulation User 0 or System)
                    with get_db() as db:
                        db.execute(
                            "INSERT INTO logs (user_id, prediction, confidence, is_threat, severity, timestamp) VALUES (?,?,?,?,?,?)",
                            (0, prediction, round(prob*100, 2), is_threat, severity, time.strftime('%Y-%m-%d %H:%M:%S'))
                        )
                        db.commit()
                
                # Emit to monitor
                socketio.emit('packet_captured', {
                    **flow_data,
                    "prediction": prediction,
                    "confidence": round(prob*100, 2),
                    "is_threat": bool(is_threat)
                })
                
            except Exception as e:
                print(f"Simulator Error: {e}")
        
        socketio.sleep(np.random.uniform(0.5, 2.0))

# ── Routes: Auth ───────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        uname = request.form.get("username", "").strip()
        pw    = request.form.get("password", "")
        with get_db() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
        
        if row and _check_pw(pw, row["password"]):
            # Migration: Re-hash if it was legacy SHA-256
            if len(row["password"]) == 64:
                new_hash = _hash(pw)
                with get_db() as db:
                    db.execute("UPDATE users SET password=? WHERE id=?", (new_hash, row["id"]))
            
            session["user_id"]  = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            flash(f"Welcome back, {row['username']}!", "success")
            return redirect(url_for("dashboard"))
        
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return render_template("register.html")
        try:
            with get_db() as db:
                user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                if not user:
                    # First user becomes admin
                    is_admin = 1 if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else 0
                    db.execute(
                        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                        (username, _hash(password), is_admin)
                    )
                    db.commit()
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
        "#00875A" if l == "normal" else
        "#E8003D" if l in ("dos","r2l","u2r") else "#E07000"
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

# ── PCAP Processor ────────────────────────────────────────────────────────
def process_pcap(filepath):
    """Converts PCAP packets into a DataFrame for ML analysis."""
    packets = rdpcap(filepath)
    rows = []
    
    # Simple flow aggregation
    for pkt in packets[:1000]: # Limit for performance
        if IP in pkt:
            row = {
                'duration':  float(pkt.time),
                'protocol':  'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'ICMP'),
                'src_bytes': len(pkt),
                'dst_bytes': 0,
                'count':     1,
                'srv_count': 1,
                'service':   'http' if (TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80)) else 'other'
            }
            rows.append(row)
    
    return pd.DataFrame(rows)

# ── Routes: Analyse / Upload ───────────────────────────────────────────────
@app.route("/analyse", methods=["GET", "POST"])
@login_required
def analyse():
    results  = None
    filename = None
    summary  = {}

    if request.method == "POST":
        f = request.files.get("csv_file")
        if not f:
            flash("No file selected.", "danger")
            return render_template("analyse.html", model_status=get_model_status())
        
        # ── Sanitization ──
        # Check extension and MIME
        allowed_ext = f.filename.lower().endswith((".csv", ".pcap", ".pcapng"))
        is_csv = f.filename.lower().endswith(".csv")
        content_type = f.content_type or ""
        
        if not allowed_ext:
            flash("Invalid file type. Only CSV/PCAP/PCAPNG allowed.", "danger")
            return render_template("analyse.html", model_status=get_model_status())
        
        if is_csv and "text/csv" not in content_type and "application/vnd.ms-excel" not in content_type:
            # Some browsers/OS send different types for CSV, so we check broadly
            pass 

        filename = f.filename
        try:
            # Read first line to check column names for injection
            f.seek(0)
            header = f.readline().decode('utf-8', errors='ignore')
            if any(char in header for char in ["<script", "javascript:", "eval(", "UNION SELECT"]):
                flash("Malicious patterns detected in file header.", "danger")
                return render_template("analyse.html", model_status=get_model_status())
            
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(filepath)

            # Process based on extension
            if filename.endswith('.pcap'):
                df = process_pcap(filepath)
            else:
                df = pd.read_csv(filepath)

            if df.empty:
                flash("File contained no valid traffic data.", "danger")
                return render_template("analyse.html", model_status=get_model_status())

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
                db.commit()

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
            
            # Emit WebSocket event for real-time updates
            socketio.emit('new_analysis', {
                "user_id": session["user_id"],
                "filename": filename,
                "summary": summary
            })
            
            # Trigger Alert if threats found
            if threat_rows > 0:
                send_security_alert({
                    "filename": filename,
                    "total": total_rows,
                    "threats": threat_rows,
                    "by_type": summary["by_type"]
                })

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

@app.route("/api/system_info")
@login_required
def api_system_info():
    """System health info: DB size, record counts, model file size."""
    uid = session["user_id"]
    with get_db() as db:
        total  = db.execute("SELECT COUNT(*) FROM logs WHERE user_id=?", (uid,)).fetchone()[0]
        threats= db.execute("SELECT COUNT(*) FROM logs WHERE user_id=? AND is_threat=1", (uid,)).fetchone()[0]
        users  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db_size    = os.path.getsize(DB) if os.path.exists(DB) else 0
    model_size = os.path.getsize(MODEL_PATH) if os.path.exists(MODEL_PATH) else 0
    return jsonify({
        "total_records": total,
        "total_threats": threats,
        "total_users":   users,
        "db_size_mb":    round(db_size / 1024 / 1024, 2),
        "model_size_kb": round(model_size / 1024, 1),
        "db_path":       os.path.basename(DB),
        "model_path":    os.path.basename(MODEL_PATH),
    })

@app.route("/api/confidence_dist")
@login_required
def api_confidence_dist():
    """Confidence score distribution in 10% buckets."""
    uid = session["user_id"]
    with get_db() as db:
        rows = db.execute(
            "SELECT confidence, is_threat FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 2000",
            (uid,)
        ).fetchall()
    buckets = {f"{i*10}-{i*10+10}": 0 for i in range(10)}
    for r in rows:
        b = min(int(r["confidence"] // 10), 9)
        key = f"{b*10}-{b*10+10}"
        buckets[key] += 1
    return jsonify([{"range": k, "count": v} for k, v in buckets.items()])

# ── Routes: Profile / Password Change ─────────────────────────────────────
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    uid = session["user_id"]
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    
    if request.method == "POST":
        current = request.form.get("current_pw", "")
        new_pw  = request.form.get("new_pw", "")
        confirm = request.form.get("confirm_pw", "")
        
        if not _check_pw(current, user["password"]):
            flash("Current password is incorrect.", "danger")
        elif len(new_pw) < 6:
            flash("New password must be at least 6 characters.", "danger")
        elif new_pw != confirm:
            flash("Passwords do not match.", "danger")
        else:
            with get_db() as db:
                db.execute("UPDATE users SET password=? WHERE id=?",
                           (_hash(new_pw), uid))
                db.commit()
            flash("Password updated successfully!", "success")
            # Update user info for rendering
            with get_db() as db:
                user = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
                
    return render_template("profile.html", user=user, model_status=get_model_status())

# ── Routes: Demo ───────────────────────────────────────────────────────────
@app.route("/demo")
@login_required
def demo():
    try:
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
            db.commit()
        flash("Demo analysis complete — 20 synthetic packets analysed.", "info")
    except Exception as e:
        flash(f"Demo failed: {e}. Try clicking 'Retrain Model' to fix incompatibilities.", "danger")
    return redirect(url_for("dashboard"))

# ── Routes: Live Monitor ──────────────────────────────────────────────────
@app.route("/monitor")
@login_required
def monitor():
    return render_template("monitor.html", sniffer_active=SNIFFER_ACTIVE)

@app.route("/api/toggle_sniffer", methods=["POST"])
@login_required
def toggle_sniffer():
    global SNIFFER_ACTIVE
    SNIFFER_ACTIVE = not SNIFFER_ACTIVE
    return jsonify(active=SNIFFER_ACTIVE)

@app.route("/export_pdf")
@login_required
def export_pdf():
    """Generates a professional PDF forensic report."""
    with get_db() as db:
        logs = db.execute(
            "SELECT prediction, confidence, severity, timestamp FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50",
            (session["user_id"],)
        ).fetchall()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("CyberSentinel Forensic Report — v3.0", styles['Title']))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Paragraph(f"Analyst: {session['username'].upper()}", styles['Normal']))
    elements.append(Spacer(1, 24))

    # Data Table
    data = [["TIMESTAMP", "THREAT_TYPE", "CONFIDENCE", "SEVERITY"]]
    for l in logs:
        data.append([l['timestamp'], l['prediction'].upper(), f"{l['confidence']}%", l['severity']])

    t = Table(data, hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.black),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(t)
    
    doc.build(elements)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"Forensic_Report_{time.strftime('%Y%m%d')}.pdf", mimetype='application/pdf')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            flash("ADMINISTRATIVE PRIVILEGES REQUIRED.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/admin")
@login_required
@admin_required
def admin():
    with get_db() as db:
        users = db.execute("SELECT * FROM users ORDER BY created DESC").fetchall()
        logs_count = db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    return render_template("admin.html", users=users, logs_count=logs_count)

@app.route("/admin/delete_log/<int:log_id>", methods=["POST"])
@login_required
@admin_required
def delete_log(log_id):
    with get_db() as db:
        db.execute("DELETE FROM logs WHERE log_id=?", (log_id,))
        db.commit()
    return jsonify(success=True)

@app.route("/threats")
@login_required
def threats():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    with get_db() as db:
        threats = db.execute(
            "SELECT * FROM logs WHERE is_threat=1 ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (per_page, offset)
        ).fetchall()
        total = db.execute("SELECT COUNT(*) FROM logs WHERE is_threat=1").fetchone()[0]
        
        by_type = db.execute(
            "SELECT prediction, COUNT(*) as cnt FROM logs WHERE is_threat=1 GROUP BY prediction ORDER BY cnt DESC"
        ).fetchall()
        
        by_severity = db.execute(
            "SELECT severity, COUNT(*) as cnt FROM logs WHERE is_threat=1 GROUP BY severity ORDER BY cnt DESC"
        ).fetchall()
        
        critical_count = db.execute(
            "SELECT COUNT(*) FROM logs WHERE severity='Critical'"
        ).fetchone()[0]

    pages = (total + per_page - 1) // per_page
    
    return render_template(
        "threats.html",
        threats=threats,
        total_threats=total,
        by_type=by_type,
        by_severity=by_severity,
        critical_count=critical_count,
        page=page,
        pages=pages
    )

@app.route("/api/live_packet")
@login_required
def api_live_packet():
    """Simulates one live incoming packet and records it."""
    # Generate 1 synthetic packet
    df = make_synthetic(1).drop(columns=["label"], errors="ignore")
    result_df = detector.predict_df(df)
    row = result_df.iloc[0]
    
    # Save to DB for history
    with get_db() as db:
        db.execute(
            """INSERT INTO logs 
               (user_id, filename, traffic_data, prediction, 
                confidence, severity, is_threat, timestamp)
               VALUES (?,?,?,?,?,?,?,?)""",
            (session["user_id"], "live_stream", "{}",
             row["prediction"], float(row["confidence"]),
             row["severity"], int(row["is_threat"]),
             datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
    
    return jsonify({
        "prediction": row["prediction"],
        "confidence": float(row["confidence"]),
        "severity": row["severity"],
        "badge_color": row["badge_color"],
        "is_threat": bool(row["is_threat"]),
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })

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
    # Start background threads
    socketio.start_background_task(background_stats_thread)
    socketio.start_background_task(packet_simulator)
    socketio.run(app, debug=True, host="0.0.0.0", port=5001)