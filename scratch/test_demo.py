import os, sys
import pandas as pd
sys.path.insert(0, os.path.join(os.getcwd(), "model"))
from threat_model import get_or_train, make_synthetic

try:
    print("Loading detector...")
    detector = get_or_train()
    print(f"Detector dataset type: {detector.dataset_type}")
    
    print("Generating synthetic data...")
    df = make_synthetic(20).drop(columns=["label"], errors="ignore")
    print(f"Generated DF with columns: {df.columns.tolist()}")
    
    print("Running prediction...")
    result_df = detector.predict_df(df)
    print("Prediction successful!")
    print(result_df[["prediction", "confidence", "severity"]].head())
    
except Exception as e:
    print(f"FAILED: {e}")
    import traceback
    traceback.print_exc()
