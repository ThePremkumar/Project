"""
Threat Detection ML Engine
Supports:
  1. CIC-IDS 2017 dataset (real network traffic — recommended)
  2. Synthetic fallback  (auto-used if no dataset found)

HOW TO USE CIC-IDS 2017:
  1. Download from: https://www.unb.ca/cic/datasets/ids-2017.html
     → Click "MachineLearningCVE" → download the CSV files
  2. Create a folder:  ictds/data/cicids/
  3. Copy the CSV files into that folder
  4. Delete model/model.pkl   (forces retrain)
  5. Restart python app.py    (auto-detects and trains on CIC-IDS)
"""
import os, pickle, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings; warnings.filterwarnings('ignore')

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
CICIDS_DIR = os.path.join(BASE_DIR, "..", "data", "cicids")

# ── CIC-IDS 2017 label  →  our 5-class system ─────────────────────────────
CICIDS_LABEL_MAP = {
    "benign":               "normal",
    "dos hulk":             "dos",
    "dos goldeneye":        "dos",
    "dos slowloris":        "dos",
    "dos slowhttptest":     "dos",
    "ddos":                 "dos",
    "heartbleed":           "dos",
    "portscan":             "probe",
    "ftp-patator":          "r2l",
    "ssh-patator":          "r2l",
    "brute force":          "r2l",
    "xss":                  "r2l",
    "sql injection":        "r2l",
    "web attack":           "r2l",
    "infiltration":         "u2r",
    "bot":                  "u2r",
}

SEVERITY = {
    "normal": "None",
    "dos":    "High",
    "probe":  "Medium",
    "r2l":    "High",
    "u2r":    "Critical",
}
COLOR = {
    "normal": "success",
    "dos":    "danger",
    "probe":  "warning",
    "r2l":    "danger",
    "u2r":    "danger",
}

# ── CIC-IDS 2017 features (78 columns, after name cleaning) ───────────────
CICIDS_FEATURES = [
    "destination_port","flow_duration","total_fwd_packets",
    "total_backward_packets","total_length_of_fwd_packets",
    "total_length_of_bwd_packets","fwd_packet_length_max",
    "fwd_packet_length_min","fwd_packet_length_mean","fwd_packet_length_std",
    "bwd_packet_length_max","bwd_packet_length_min","bwd_packet_length_mean",
    "bwd_packet_length_std","flow_bytes/s","flow_packets/s",
    "flow_iat_mean","flow_iat_std","flow_iat_max","flow_iat_min",
    "fwd_iat_total","fwd_iat_mean","fwd_iat_std","fwd_iat_max","fwd_iat_min",
    "bwd_iat_total","bwd_iat_mean","bwd_iat_std","bwd_iat_max","bwd_iat_min",
    "fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
    "fwd_header_length","bwd_header_length","fwd_packets/s","bwd_packets/s",
    "min_packet_length","max_packet_length","packet_length_mean",
    "packet_length_std","packet_length_variance","fin_flag_count",
    "syn_flag_count","rst_flag_count","psh_flag_count","ack_flag_count",
    "urg_flag_count","cwe_flag_count","ece_flag_count","down/up_ratio",
    "average_packet_size","avg_fwd_segment_size","avg_bwd_segment_size",
    "fwd_avg_bytes/bulk","fwd_avg_packets/bulk","fwd_avg_bulk_rate",
    "bwd_avg_bytes/bulk","bwd_avg_packets/bulk","bwd_avg_bulk_rate",
    "subflow_fwd_packets","subflow_fwd_bytes","subflow_bwd_packets",
    "subflow_bwd_bytes","init_win_bytes_forward","init_win_bytes_backward",
    "act_data_pkt_fwd","min_seg_size_forward","active_mean","active_std",
    "active_max","active_min","idle_mean","idle_std","idle_max","idle_min",
]

# ── NSL-KDD style columns (synthetic fallback) ────────────────────────────
NUMERIC_COLS = [
    "duration","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
    "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
]
CAT_COLS = ["protocol_type", "service", "flag"]


# ══════════════════════════════════════════════════════════════════════════
#  CIC-IDS 2017 Loader
# ══════════════════════════════════════════════════════════════════════════

def load_cicids(cicids_dir=CICIDS_DIR, max_per_file=50000):
    """
    Load CIC-IDS 2017 CSV files from cicids_dir.
    Returns a cleaned DataFrame ready for training, or None if no files found.
    """
    if not os.path.isdir(cicids_dir):
        return None

    csv_files = [f for f in os.listdir(cicids_dir) if f.lower().endswith(".csv")]
    if not csv_files:
        return None

    frames = []
    for fname in sorted(csv_files):
        path = os.path.join(cicids_dir, fname)
        try:
            print(f"[cicids] Reading {fname} …")
            df = pd.read_csv(path, low_memory=False)

            # clean column names
            df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

            # find label column
            label_col = next((c for c in df.columns if "label" in c), None)
            if label_col is None:
                print(f"  ↳ skipped (no label column)")
                continue
            df = df.rename(columns={label_col: "label"})

            # map labels → 5 classes
            df["label"] = (
                df["label"].astype(str).str.strip().str.lower()
                           .map(CICIDS_LABEL_MAP)
                           .fillna("probe")
            )

            # sample if large
            if len(df) > max_per_file:
                df = df.sample(max_per_file, random_state=42)

            counts = df["label"].value_counts().to_dict()
            print(f"  ↳ {len(df):,} rows  |  {counts}")
            frames.append(df)

        except Exception as e:
            print(f"  ↳ ERROR: {e}")

    if not frames:
        return None

    combined = pd.concat(frames, ignore_index=True)
    print(f"[cicids] Total: {len(combined):,} rows across {len(frames)} file(s)")
    return combined


# ══════════════════════════════════════════════════════════════════════════
#  ThreatDetector
# ══════════════════════════════════════════════════════════════════════════

class ThreatDetector:
    def __init__(self):
        self.rf  = RandomForestClassifier(
            n_estimators=150, max_depth=20,
            class_weight="balanced", random_state=42, n_jobs=-1
        )
        self.gb  = GradientBoostingClassifier(
            n_estimators=80, learning_rate=0.1, max_depth=5, random_state=42
        )
        self.scaler        = StandardScaler()
        self.encoders      = {}
        self.le            = LabelEncoder()
        self.feature_names = []
        self.fitted        = False
        self.dataset_type  = "synthetic"

    # ── safe column getter ─────────────────────────────────────────────────
    def _col(self, df, name, default=0):
        if name in df.columns:
            return pd.to_numeric(df[name], errors="coerce").fillna(default)
        return pd.Series(default, index=df.index, dtype=float)

    # ── categorical encoder ────────────────────────────────────────────────
    def _encode_cat(self, df, fit=True):
        df = df.copy()
        for c in CAT_COLS:
            if c not in df.columns:
                df[c] = "tcp"
            if fit:
                le = LabelEncoder()
                df[c] = le.fit_transform(df[c].astype(str))
                self.encoders[c] = le
            else:
                le = self.encoders.get(c)
                if le:
                    known = set(le.classes_)
                    df[c] = df[c].apply(
                        lambda x: x if str(x) in known else le.classes_[0]
                    )
                    df[c] = le.transform(df[c].astype(str))
                else:
                    df[c] = 0
        return df

    # ── feature engineering (synthetic / NSL-KDD style) ───────────────────
    def _engineer(self, df):
        df = df.copy()
        df["byte_ratio"]    = self._col(df,"src_bytes") / (self._col(df,"dst_bytes") + 1)
        df["error_combo"]   = self._col(df,"serror_rate") + self._col(df,"rerror_rate")
        srate = self._col(df,"same_srv_rate")
        df["traffic_ent"]   = (srate * np.log1p(srate)).fillna(0)
        df["conn_burst"]    = (self._col(df,"count") > 200).astype(int)
        df["root_activity"] = (
            (self._col(df,"num_root") > 0) | (self._col(df,"root_shell") > 0)
        ).astype(int)
        return df

    # ── build feature matrix ───────────────────────────────────────────────
    def _get_X(self, df, fit=True):
        if self.dataset_type == "cicids":
            return self._get_X_cicids(df, fit)
        return self._get_X_synthetic(df, fit)

    def _get_X_cicids(self, df, fit=True):
        df = df.copy()
        use = [c for c in CICIDS_FEATURES if c in df.columns]
        for c in use:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
        df[use] = df[use].replace([np.inf, -np.inf], 0)
        if fit:
            self.feature_names = use
        else:
            for c in self.feature_names:
                if c not in df.columns:
                    df[c] = 0
            use = self.feature_names
        X = df[use].values
        return self.scaler.fit_transform(X) if fit else self.scaler.transform(X)

    def _get_X_synthetic(self, df, fit=True):
        df = df.copy()
        for c in NUMERIC_COLS:
            if c not in df.columns:
                df[c] = 0
            else:
                df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
        df = self._engineer(df)
        df = self._encode_cat(df, fit=fit)
        extra = ["byte_ratio","error_combo","traffic_ent","conn_burst","root_activity"]
        cols  = [c for c in NUMERIC_COLS + CAT_COLS + extra if c in df.columns]
        if fit:
            self.feature_names = cols
        else:
            for c in self.feature_names:
                if c not in df.columns:
                    df[c] = 0
            cols = self.feature_names
        X = df[cols].fillna(0).values
        return self.scaler.fit_transform(X) if fit else self.scaler.transform(X)

    # ── train ──────────────────────────────────────────────────────────────
    def train(self, df, label_col="label", dataset_type="synthetic"):
        self.dataset_type = dataset_type
        print(f"[model] Dataset      : {dataset_type}")
        print(f"[model] Training rows: {len(df):,}")
        print(f"[model] Classes      : {df[label_col].value_counts().to_dict()}")

        X = self._get_X(df, fit=True)
        y = self.le.fit_transform(df[label_col].astype(str))

        X_tr, X_val, y_tr, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        print("[model] Fitting Random Forest …")
        self.rf.fit(X_tr, y_tr)
        print("[model] Fitting Gradient Boosting …")
        self.gb.fit(X_tr, y_tr)
        self.fitted = True

        preds  = self._vote(X_val)
        acc    = accuracy_score(y_val, preds)
        report = classification_report(
            y_val, preds, target_names=self.le.classes_, zero_division=0
        )
        self.save()
        return acc, report

    def _vote(self, X):
        p1 = self.rf.predict_proba(X)
        p2 = self.gb.predict_proba(X)
        return np.argmax((p1 + p2) / 2, axis=1)

    # ── predict ────────────────────────────────────────────────────────────
    def predict_df(self, df):
        assert self.fitted, "Model not trained yet"
        X      = self._get_X(df, fit=False)
        idx    = self._vote(X)
        avg_p  = (self.rf.predict_proba(X) + self.gb.predict_proba(X)) / 2
        conf   = np.max(avg_p, axis=1)
        labels = self.le.inverse_transform(idx)

        out = df.copy()
        out["prediction"]  = labels
        out["confidence"]  = np.round(conf * 100, 1)
        out["severity"]    = [SEVERITY.get(l, "Unknown") for l in labels]
        out["badge_color"] = [COLOR.get(l, "secondary")  for l in labels]
        out["is_threat"]   = out["prediction"] != "normal"
        return out

    # ── save / load ────────────────────────────────────────────────────────
    def save(self):
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self, f)
        print(f"[model] Saved → {MODEL_PATH}")

    @classmethod
    def load(cls):
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, "rb") as f:
                return pickle.load(f)
        return None


# ══════════════════════════════════════════════════════════════════════════
#  Synthetic fallback data generator
# ══════════════════════════════════════════════════════════════════════════

def make_synthetic(n=6000):
    rng    = np.random.default_rng(42)
    labels = rng.choice(
        ["normal","dos","probe","r2l","u2r"], n,
        p=[0.55, 0.20, 0.12, 0.08, 0.05]
    )
    df = pd.DataFrame({
        "duration":           rng.exponential(10, n).clip(0, 5000),
        "protocol_type":      rng.choice(["tcp","udp","icmp"], n),
        "service":            rng.choice(["http","ftp","smtp","ssh","dns","telnet"], n),
        "flag":               rng.choice(["SF","S0","REJ","RSTO","SH"], n),
        "src_bytes":          rng.exponential(2000, n).astype(int),
        "dst_bytes":          rng.exponential(3000, n).astype(int),
        "land":               rng.integers(0, 2, n),
        "wrong_fragment":     rng.poisson(0.02, n).clip(0, 3),
        "urgent":             rng.integers(0, 2, n),
        "hot":                rng.poisson(1, n).clip(0, 30),
        "num_failed_logins":  rng.poisson(0.05, n).clip(0, 5),
        "logged_in":          rng.integers(0, 2, n),
        "num_compromised":    rng.poisson(0.1, n).clip(0, 10),
        "root_shell":         rng.integers(0, 2, n),
        "su_attempted":       rng.integers(0, 2, n),
        "num_root":           rng.poisson(0.02, n).clip(0, 5),
        "num_file_creations": rng.poisson(0.1, n).clip(0, 20),
        "num_shells":         rng.poisson(0.01, n).clip(0, 5),
        "num_access_files":   rng.poisson(0.2, n).clip(0, 10),
        "num_outbound_cmds":  rng.integers(0, 2, n),
        "is_host_login":      rng.integers(0, 2, n),
        "is_guest_login":     rng.integers(0, 2, n),
        "count":              rng.integers(1, 512, n),
        "srv_count":          rng.integers(1, 512, n),
        "serror_rate":        rng.beta(1, 10, n),
        "srv_serror_rate":    rng.beta(1, 10, n),
        "rerror_rate":        rng.beta(1, 10, n),
        "srv_rerror_rate":    rng.beta(1, 10, n),
        "same_srv_rate":      rng.beta(5, 2, n),
        "diff_srv_rate":      rng.beta(1, 5, n),
        "srv_diff_host_rate": rng.beta(1, 5, n),
        "dst_host_count":     rng.integers(1, 256, n),
        "dst_host_srv_count": rng.integers(1, 256, n),
        "dst_host_same_srv_rate":      rng.beta(5, 2, n),
        "dst_host_diff_srv_rate":      rng.beta(1, 5, n),
        "dst_host_same_src_port_rate": rng.beta(3, 2, n),
        "dst_host_srv_diff_host_rate": rng.beta(1, 5, n),
        "dst_host_serror_rate":        rng.beta(1, 10, n),
        "dst_host_srv_serror_rate":    rng.beta(1, 10, n),
        "dst_host_rerror_rate":        rng.beta(1, 10, n),
        "dst_host_srv_rerror_rate":    rng.beta(1, 10, n),
        "label": labels,
    })
    dos = df["label"] == "dos"
    df.loc[dos, "count"]       = rng.integers(400, 512, dos.sum())
    df.loc[dos, "serror_rate"] = rng.uniform(0.8, 1.0, dos.sum())
    u2r = df["label"] == "u2r"
    df.loc[u2r, "root_shell"]  = 1
    df.loc[u2r, "num_root"]    = rng.integers(1, 10, u2r.sum())
    return df


# ══════════════════════════════════════════════════════════════════════════
#  Smart loader — CIC-IDS first, synthetic fallback
# ══════════════════════════════════════════════════════════════════════════

def get_or_train():
    # 1. Load saved model if exists
    det = ThreatDetector.load()
    if det and det.fitted:
        print(f"[model] Loaded saved model (dataset: {det.dataset_type})")
        return det

    det = ThreatDetector()

    # 2. Try CIC-IDS 2017
    cicids_df = load_cicids(CICIDS_DIR)
    if cicids_df is not None and len(cicids_df) > 100:
        print("[model] Training on CIC-IDS 2017 …")
        acc, rep = det.train(cicids_df, label_col="label", dataset_type="cicids")
        print(f"[model] CIC-IDS Accuracy = {acc:.4f}")
        print(rep)
        return det

    # 3. Synthetic fallback
    print("[model] Training on synthetic data (no CIC-IDS files found) …")
    print(f"[model] Tip: place CIC-IDS CSV files in  {os.path.abspath(CICIDS_DIR)}")
    df  = make_synthetic(6000)
    acc, rep = det.train(df, label_col="label", dataset_type="synthetic")
    print(f"[model] Synthetic Accuracy = {acc:.4f}")
    return det