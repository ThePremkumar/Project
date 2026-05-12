import pickle, os, sys
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "..", "model"))
import threat_model
MODEL_PATH = os.path.join(BASE_DIR, "..", "model", "model.pkl")

if os.path.exists(MODEL_PATH):
    with open(MODEL_PATH, "rb") as f:
        det = pickle.load(f)
        print(f"Attributes: {dir(det)}")
        print(f"Fitted: {getattr(det, 'fitted', 'N/A')}")
        print(f"Model exists: {hasattr(det, 'model')}")
        if hasattr(det, 'model'):
            print(f"Model type: {type(det.model)}")
else:
    print("No model.pkl found")
