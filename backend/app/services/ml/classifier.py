from __future__ import annotations

from pathlib import Path

from app.core.config import BACKEND_ROOT
from app.services.ml.features import extract_features, feature_vector

MODEL_PATH = BACKEND_ROOT / "data" / "ml_model.joblib"


def ml_status() -> dict:
    return {
        "enabled": MODEL_PATH.exists(),
        "model_version": "untrained" if not MODEL_PATH.exists() else "local-experimental",
        "limitations": [
            "ML output is experimental and separate from deterministic rule findings.",
            "No licensed external phishing corpus is bundled. Train later with an approved dataset.",
            "Do not treat an ML label as proof of malice or safety.",
        ],
    }


def predict_optional(parsed, url_results, attachment_results, findings) -> dict:
    status = ml_status()
    features = extract_features(parsed, url_results, attachment_results, findings)
    if not MODEL_PATH.exists():
        return {
            **status,
            "prediction": None,
            "features": features,
            "reason": "No trained model artifact is present. Core analysis does not require ML.",
        }
    try:
        import joblib

        bundle = joblib.load(MODEL_PATH)
        model = bundle["model"]
        vector = [feature_vector(features)]
        label = str(model.predict(vector)[0])
        proba = None
        if hasattr(model, "predict_proba"):
            proba = {str(cls): float(p) for cls, p in zip(model.classes_, model.predict_proba(vector)[0])}
        return {
            **status,
            "prediction": label,
            "probabilities": proba,
            "features": features,
            "model_version": bundle.get("version", "local-experimental"),
        }
    except Exception as exc:
        return {
            **status,
            "prediction": None,
            "features": features,
            "reason": f"Model load or inference failed: {exc.__class__.__name__}",
        }
