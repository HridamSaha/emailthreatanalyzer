"""Train an optional experimental classifier on synthetic features only.

This script does not use a real-world malware or phishing corpus. Results are
for interface demonstration and must not be reported as operational accuracy.
"""

from __future__ import annotations

import json
from pathlib import Path

# Synthetic, clearly labeled lab data — not a production dataset.
SYNTHETIC = [
    ({"url_count": 0, "suspicious_url_count": 0, "sender_mismatch": 0, "credential_request": 0, "attachment_count": 0, "risky_attachment_count": 0, "body_length": 120, "exclamation_count": 0, "finding_count": 0}, "safe"),
    ({"url_count": 1, "suspicious_url_count": 1, "sender_mismatch": 0, "credential_request": 0, "attachment_count": 0, "risky_attachment_count": 0, "body_length": 80, "exclamation_count": 0, "finding_count": 1}, "suspicious"),
    ({"url_count": 2, "suspicious_url_count": 2, "sender_mismatch": 1, "credential_request": 1, "attachment_count": 1, "risky_attachment_count": 1, "body_length": 400, "exclamation_count": 4, "finding_count": 5}, "malicious"),
]


def main() -> None:
    try:
        from sklearn.ensemble import RandomForestClassifier
        import joblib
        import numpy as np
    except ImportError:
        print("Install optional extras first: pip install -r requirements-ml.txt")
        return

    from app.core.config import BACKEND_ROOT
    from app.services.ml.features import feature_vector

    x = np.array([feature_vector(row[0]) for row in SYNTHETIC])
    y = np.array([row[1] for row in SYNTHETIC])
    model = RandomForestClassifier(n_estimators=10, random_state=0)
    # Tiny synthetic set: documented as non-evaluable for real performance.
    model.fit(x, y)
    out = BACKEND_ROOT / "data"
    out.mkdir(exist_ok=True)
    joblib.dump({"model": model, "version": "synthetic-demo-0.1"}, out / "ml_model.joblib")
    metrics = {
        "note": "Training used three synthetic rows. Metrics are not scientifically valid.",
        "n_samples": len(SYNTHETIC),
        "classes": sorted(set(y.tolist())),
    }
    (out / "ml_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("Wrote optional model artifacts. Do not cite these as accuracy results.")


if __name__ == "__main__":
    main()
