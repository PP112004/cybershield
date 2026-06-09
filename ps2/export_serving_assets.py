"""Export serving assets derived from the final PS2 key-features model:

  artifacts/thresholds.json   — alert/borderline score thresholds anchored to
                                the alert-budget quantiles of training scores
                                (top 1% -> alert, top 5% -> borderline)
  serving/app/examples.json   — pre-built demo accounts (clear mule / clear
                                legit / borderline) for the hosted demo, since
                                anonymized F-features can't be hand-crafted
                                by a judge.

Run after ps2_train_eval.py (from the repo root):
    python3 ps2/export_serving_assets.py
"""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = REPO_ROOT / "artifacts"
EXAMPLES_PATH = REPO_ROOT / "serving" / "app" / "examples.json"
TARGET = "F3924"


def jsonable(v):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return None
    if isinstance(v, (np.integer,)):
        return int(v)
    if isinstance(v, (np.floating,)):
        return float(v)
    return v


def main() -> None:
    with open(ARTIFACTS / "model_key18_lgbm.pkl", "rb") as f:
        bundle = pickle.load(f)
    model, features = bundle["model"], bundle["features"]

    df = pd.read_csv(REPO_ROOT / "data" / "DataSet.csv", low_memory=False,
                     usecols=features + [TARGET])
    y = df.pop(TARGET).astype(int)
    X = df[features].copy()
    categories = bundle.get("categories") or {}
    for c in features:
        if X[c].dtype == object or str(X[c].dtype) == "str":
            X[c] = pd.Categorical(
                X[c], categories=categories.get(c) or sorted(X[c].dropna().unique()))
    scores = model.predict_proba(X)[:, 1]

    thresholds = {
        "alert": float(np.quantile(scores, 0.99)),      # top 1% = alert budget
        "borderline": float(np.quantile(scores, 0.95)),  # top 5% = review queue
    }
    (ARTIFACTS / "thresholds.json").write_text(json.dumps(thresholds, indent=2))

    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    mid = (thresholds["alert"] + thresholds["borderline"]) / 2
    picks = {
        "clear_mule": pos[np.argmax(scores[pos])],
        "clear_legit": neg[np.argmin(scores[neg])],
        "borderline": int(np.argmin(np.abs(scores - mid))),
    }
    examples = {}
    for name, idx in picks.items():
        examples[name] = {
            "description": {
                "clear_mule": "Confirmed mule account, highest model score",
                "clear_legit": "Legitimate account, lowest model score",
                "borderline": "Score sits between the borderline and alert "
                              "thresholds — the watchlist-promotion demo case",
            }[name],
            "actual_label": int(y.iloc[idx]),
            "model_score": round(float(scores[idx]), 6),
            "features": {f: jsonable(df.iloc[int(idx)][f]) for f in features},
        }
    EXAMPLES_PATH.write_text(json.dumps(examples, indent=2))

    print("thresholds:", thresholds)
    for name, ex in examples.items():
        print(f"  {name}: label={ex['actual_label']} score={ex['model_score']}")


if __name__ == "__main__":
    main()
