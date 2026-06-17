"""PS2 scoring: load the key-features LightGBM model, score one account,
and produce SHAP reason codes via LightGBM's native pred_contrib (exact
TreeSHAP — no shap dependency needed at serving time)."""

from __future__ import annotations

import json
import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parents[1]

MODEL_PATH = Path(os.environ.get(
    "MODEL_PATH", REPO_ROOT / "artifacts" / "model_key18_lgbm.pkl"))
THRESHOLDS_PATH = Path(os.environ.get(
    "THRESHOLDS_PATH", REPO_ROOT / "artifacts" / "thresholds.json"))
META_PATH = APP_DIR / "meta.json"

# Used only if thresholds.json is absent; the real values are the model's
# training-score quantiles written by ps2_train_eval.py.
DEFAULT_THRESHOLDS = {"alert": 0.90, "borderline": 0.50}


class Scorer:
    def __init__(self) -> None:
        with open(MODEL_PATH, "rb") as f:
            bundle = pickle.load(f)
        self.model = bundle["model"]
        self.features: list[str] = bundle["features"]

        meta = json.loads(META_PATH.read_text())
        # Category levels: prefer the ones saved with the model; fall back to
        # meta.json (levels are lexicographically sorted in both, matching
        # pandas' astype("category") behavior at training time).
        self.categories: dict[str, list[str]] = bundle.get(
            "categories") or meta["categories"]

        if THRESHOLDS_PATH.exists():
            self.thresholds = json.loads(THRESHOLDS_PATH.read_text())
        else:
            self.thresholds = dict(DEFAULT_THRESHOLDS)

    def _to_frame(self, payload: dict) -> pd.DataFrame:
        row = {f: payload.get(f) for f in self.features}
        X = pd.DataFrame([row])
        for col in self.features:
            if col in self.categories:
                X[col] = pd.Categorical(X[col],
                                        categories=self.categories[col])
            else:
                X[col] = pd.to_numeric(X[col], errors="coerce")
        return X

    def score(self, payload: dict, top_n: int = 5) -> dict:
        X = self._to_frame(payload)
        prob = float(self.model.predict_proba(X)[0, 1])

        # pred_contrib -> per-feature TreeSHAP contributions (+ base value).
        contrib = self.model.booster_.predict(X, pred_contrib=True)[0]
        shap_vals = contrib[:-1]
        order = np.argsort(np.abs(shap_vals))[::-1][:top_n]
        reason_codes = []
        for i in order:
            feat = self.features[i]
            val = payload.get(feat)
            reason_codes.append({
                "feature": feat,
                "value": val,
                "shap": round(float(shap_vals[i]), 4),
                "direction": "raises risk" if shap_vals[i] > 0 else "lowers risk",
            })

        if prob >= self.thresholds["alert"]:
            band = "alert"
        elif prob >= self.thresholds["borderline"]:
            band = "borderline"
        else:
            band = "clear"

        return {
            "probability": round(prob, 6),
            "risk_band": band,
            "thresholds": self.thresholds,
            "reason_codes": reason_codes,
            "model": "key18_lgbm_weighted",
            "calibration_caveat": (
                "Score is an uncalibrated upper bound: in the provided dataset "
                "the extraction batch (F2230) is confounded with the label, so "
                "the model partly separates on batch rather than fraud. Use the "
                "score as a relative ranking for alert triage, not as an "
                "absolute fraud probability, until retrained on matched windows."
            ),
        }
