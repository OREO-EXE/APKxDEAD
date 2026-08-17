from pathlib import Path
import json
import joblib
import xgboost as xgb
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = PROJECT_ROOT / "models" / "apk_malware_model.json"
LABEL_PATH = PROJECT_ROOT / "models" / "label_encoder.pkl"
FEATURE_PATH = PROJECT_ROOT / "models" / "feature_columns.json"


print("Loading model...")

model = xgb.XGBClassifier()
model.load_model(MODEL_PATH)

label_encoder = joblib.load(LABEL_PATH)

with open(FEATURE_PATH, "r") as f:
    feature_columns = json.load(f)

print("Model loaded successfully!")
print("Features:", len(feature_columns))
print("Classes:", list(label_encoder.classes_))


def predict_malware(features: dict):

    df = pd.DataFrame([features])

    # Add missing features
    for column in feature_columns:
        if column not in df.columns:
            df[column] = 0

    # EXACT same feature order used during training
    df = df[feature_columns]

    prediction = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]

    prediction = int(prediction)

    family = label_encoder.inverse_transform(
        [prediction]
    )[0]

    confidence = float(probabilities[prediction])

    return {
        "family": family,
        "confidence": confidence,
        "prediction_id": prediction
    }