"""PS2 — Mule Account Classification: reproducible train/eval script.

Implements the evaluation methodology from ARCHITECTURE.md §4.2:

  1. Leakage audit      — flag features with near-perfect single-feature separation
                          (value AUC or missingness AUC >= threshold) and exclude them.
  2. Honest evaluation  — repeated stratified CV (81 positives make a single split
                          meaningless); PR-AUC with percentile intervals; precision/
                          recall/lift at a fixed alert budget (top 1% of accounts).
  3. Imbalance strategy — class-weighted gradient boosting as the primary approach;
                          SMOTE kept only as a compared baseline.
  4. Two-model strategy — (a) compact interpretable model on the 18 bank-identified
                          key features; (b) full-feature discovery model whose SHAP
                          importances surface NEW predictive features beyond the 18.
  5. Artifacts          — refit-on-all-data models (.pkl), metrics.json, leakage
                          audit CSV, SHAP importance CSV, and a markdown results
                          report under artifacts/.

Usage (from the repo root):
    python3 ps2/ps2_train_eval.py            # full run: 5-fold x 5-repeat CV
    python3 ps2/ps2_train_eval.py --quick    # smoke test: 3-fold x 1-repeat
"""

from __future__ import annotations

import argparse
import json
import pickle
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.model_selection import RepeatedStratifiedKFold
from sklearn.metrics import average_precision_score, roc_auc_score
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = REPO_ROOT / "data" / "DataSet.csv"
ARTIFACTS = REPO_ROOT / "artifacts"

SEED = 42
TARGET = "F3924"
ALERT_BUDGET = 0.01  # banks review the top 1% of accounts
LEAKAGE_AUC_THRESHOLD = 0.985

KEY_FEATURES = [
    "F115", "F321", "F527", "F531", "F670", "F1692", "F2082", "F2122",
    "F2582", "F2678", "F2737", "F2956", "F3043", "F3836", "F3887",
    "F3889", "F3891", "F3894",
]

# String columns found by data inspection (everything else is numeric).
DATE_COL = "F3888"     # account-open date, m-d-YYYY -> engineered to age in days
MONTH_COL = "F2230"    # report month label (Sep25..Dec25) -> ordinal index
CAT_COLS = ["F3886", "F3889", "F3890", "F3891", "F3892", "F3893"]

REFERENCE_DATE = pd.Timestamp("2026-01-01")  # data's months run up to Dec25


# --------------------------------------------------------------------------
# Data loading & preprocessing
# --------------------------------------------------------------------------

def load_data() -> tuple[pd.DataFrame, pd.Series]:
    df = pd.read_csv(DATA_PATH, low_memory=False)
    df = df.drop(columns=["Unnamed: 0"], errors="ignore")
    y = df.pop(TARGET).astype(int)

    # Date -> account age in days (missing/unparseable stays NaN).
    dates = pd.to_datetime(df[DATE_COL], format="%m-%d-%Y", errors="coerce")
    df[DATE_COL] = (REFERENCE_DATE - dates).dt.days.astype("float64")

    # Month label -> ordinal index (Sep25=0 .. Dec25=3).
    month_order = {"Sep25": 0, "Oct25": 1, "Nov25": 2, "Dec25": 3}
    df[MONTH_COL] = df[MONTH_COL].map(month_order).astype("float64")

    for c in CAT_COLS:
        df[c] = df[c].astype("category")

    # Drop fully-empty and constant columns (uninformative by construction).
    n_unique = df.nunique(dropna=True)
    dead = n_unique[n_unique <= 1].index.tolist()
    df = df.drop(columns=dead)
    print(f"loaded {df.shape[0]} rows, {df.shape[1]} features "
          f"({len(dead)} empty/constant dropped), positives={int(y.sum())}")

    # Missingness is signal (§4.2): row-level NA count as an explicit feature.
    # GBMs already learn per-feature NaN routing natively, so we do NOT impute.
    df["NA_COUNT"] = df.isna().sum(axis=1).astype("float64")
    return df, y


# --------------------------------------------------------------------------
# Leakage audit
# --------------------------------------------------------------------------

def fast_auc(values: np.ndarray, target: np.ndarray) -> float:
    """Rank-based AUC of a single feature vs the target (NaNs excluded)."""
    mask = ~np.isnan(values)
    v, t = values[mask], target[mask]
    n_pos, n_neg = int(t.sum()), int((1 - t).sum())
    if n_pos < 5 or n_neg < 5:
        return np.nan
    ranks = pd.Series(v).rank().to_numpy()
    return (ranks[t == 1].mean() - (n_pos + 1) / 2) / n_neg


def category_rate_auc(s: pd.Series, target: np.ndarray) -> float:
    """AUC when each category is scored by its positive rate. Catches
    NON-monotonic separators a rank AUC misses — e.g. F2230 (report month),
    where every negative sits in one batch and every positive in the others.
    Restricted to low-cardinality features, where this is a separation test
    rather than target-encoding overfit."""
    if s.nunique(dropna=True) > 50:
        return np.nan
    codes = s.astype("category").cat.codes.to_numpy()
    rates = pd.Series(target).groupby(codes).mean()
    scores = pd.Series(codes).map(rates).to_numpy(dtype="float64").copy()
    scores[codes == -1] = np.nan
    return fast_auc(scores, target)


def leakage_audit(df: pd.DataFrame, y: pd.Series) -> tuple[list[str], pd.DataFrame]:
    """Flag features whose values, category membership, OR missingness pattern
    nearly perfectly separate the classes — likely post-outcome artifacts
    (e.g. 'account frozen') or dataset-construction batch effects, which
    would deploy uselessly."""
    target = y.to_numpy()
    rows = []
    for col in df.columns:
        s = df[col]
        vals = s.cat.codes.replace(-1, np.nan).to_numpy(dtype="float64") \
            if isinstance(s.dtype, pd.CategoricalDtype) else s.to_numpy(dtype="float64")
        value_auc = fast_auc(vals, target)
        cat_auc = category_rate_auc(s, target)
        na = s.isna().to_numpy(dtype="float64")
        miss_auc = fast_auc(na, target) if 0 < na.sum() < len(na) else np.nan
        rows.append((col, value_auc, cat_auc, miss_auc))

    audit = pd.DataFrame(rows, columns=["feature", "value_auc",
                                        "category_rate_auc", "missingness_auc"])
    for c in ["value_auc", "category_rate_auc", "missingness_auc"]:
        audit[c + "_sep"] = (audit[c] - 0.5).abs() + 0.5  # symmetric separation
    audit["flagged"] = (
        (audit["value_auc_sep"] >= LEAKAGE_AUC_THRESHOLD)
        | (audit["category_rate_auc_sep"] >= LEAKAGE_AUC_THRESHOLD)
        | (audit["missingness_auc_sep"] >= LEAKAGE_AUC_THRESHOLD)
    )
    flagged = audit.loc[audit["flagged"], "feature"].tolist()
    print(f"leakage audit: {len(flagged)} feature(s) flagged at "
          f"AUC>={LEAKAGE_AUC_THRESHOLD}: {flagged}")
    return flagged, audit.sort_values("value_auc_sep", ascending=False)


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

def make_models(scale_pos_weight: float) -> dict:
    """Model zoo for CV comparison. Class weighting is the primary imbalance
    strategy; SMOTE is included only as the compared baseline (§4.2)."""
    from imblearn.over_sampling import SMOTE
    from imblearn.pipeline import Pipeline as ImbPipeline
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import OneHotEncoder

    lgbm_params = dict(
        n_estimators=400, learning_rate=0.05, num_leaves=15,
        min_child_samples=10, colsample_bytree=0.8, subsample=0.8,
        subsample_freq=1, scale_pos_weight=scale_pos_weight,
        random_state=SEED, n_jobs=-1, verbosity=-1,
    )
    xgb_params = dict(
        n_estimators=400, learning_rate=0.05, max_depth=4,
        min_child_weight=3, colsample_bytree=0.5, subsample=0.8,
        scale_pos_weight=scale_pos_weight, random_state=SEED,
        n_jobs=-1, tree_method="hist", eval_metric="aucpr",
    )

    key_num = [f for f in KEY_FEATURES if f not in ("F3889", "F3891")]
    key_cat = ["F3889", "F3891"]
    smote_pre = ColumnTransformer([
        ("num", SimpleImputer(strategy="median"), key_num),
        ("cat", OneHotEncoder(handle_unknown="ignore"), key_cat),
    ])
    smote_pipe = ImbPipeline([
        ("pre", smote_pre),
        ("smote", SMOTE(random_state=SEED, k_neighbors=5)),
        ("clf", LGBMClassifier(**{**lgbm_params, "scale_pos_weight": 1.0})),
    ])

    return {
        "key18_lgbm_weighted": ("key", LGBMClassifier(**lgbm_params)),
        "key18_lgbm_smote": ("key", smote_pipe),
        "full_lgbm_weighted": ("full", LGBMClassifier(**lgbm_params)),
        "full_xgb_weighted": ("full", XGBClassifier(**xgb_params)),
    }


def encode_for_xgb(X: pd.DataFrame) -> pd.DataFrame:
    """XGBoost path: ordinal-encode categoricals (codes, NaN=-1 -> NaN) so
    SHAP TreeExplainer works without categorical-dtype edge cases."""
    X = X.copy()
    for c in X.select_dtypes(include="category").columns:
        X[c] = X[c].cat.codes.replace(-1, np.nan).astype("float64")
    return X


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------

def budget_metrics(y_true: np.ndarray, scores: np.ndarray, budget: float) -> dict:
    """Precision/recall/lift when only the top `budget` fraction is alerted —
    the metric a bank's review team actually operates on."""
    k = max(1, int(round(budget * len(y_true))))
    top = np.argsort(scores)[::-1][:k]
    tp = int(y_true[top].sum())
    base_rate = y_true.mean()
    return {
        "alerts": k,
        "precision_at_budget": tp / k,
        "recall_at_budget": tp / max(1, int(y_true.sum())),
        "lift_at_budget": (tp / k) / base_rate if base_rate > 0 else np.nan,
    }


def summarize(values: list[float]) -> dict:
    arr = np.array(values, dtype="float64")
    return {
        "mean": float(arr.mean()),
        "std": float(arr.std(ddof=1)) if len(arr) > 1 else 0.0,
        "p2.5": float(np.percentile(arr, 2.5)),
        "p97.5": float(np.percentile(arr, 97.5)),
    }


def cross_validate(df: pd.DataFrame, y: pd.Series, flagged: list[str],
                   n_splits: int, n_repeats: int) -> dict:
    X_full = df.drop(columns=flagged, errors="ignore")
    X_key = df[KEY_FEATURES]
    spw = float((y == 0).sum() / (y == 1).sum())
    models = make_models(spw)
    cv = RepeatedStratifiedKFold(n_splits=n_splits, n_repeats=n_repeats,
                                 random_state=SEED)

    raw = {name: {"pr_auc": [], "roc_auc": [], "precision_at_budget": [],
                  "recall_at_budget": [], "lift_at_budget": []}
           for name in models}

    for fold_i, (tr, va) in enumerate(cv.split(X_full, y)):
        y_tr, y_va = y.iloc[tr], y.iloc[va].to_numpy()
        for name, (which, model) in make_models(spw).items():
            X = X_key if which == "key" else X_full
            X_tr, X_va = X.iloc[tr], X.iloc[va]
            if isinstance(model, XGBClassifier):
                X_tr, X_va = encode_for_xgb(X_tr), encode_for_xgb(X_va)
            model.fit(X_tr, y_tr)
            scores = model.predict_proba(X_va)[:, 1]
            raw[name]["pr_auc"].append(average_precision_score(y_va, scores))
            raw[name]["roc_auc"].append(roc_auc_score(y_va, scores))
            for k, v in budget_metrics(y_va, scores, ALERT_BUDGET).items():
                if k != "alerts":
                    raw[name][k].append(v)
        print(f"  fold {fold_i + 1}/{n_splits * n_repeats} done", flush=True)

    return {name: {metric: summarize(vals) for metric, vals in metrics.items()}
            for name, metrics in raw.items()}


# --------------------------------------------------------------------------
# Final models + SHAP feature discovery
# --------------------------------------------------------------------------

def fit_final_and_shap(df: pd.DataFrame, y: pd.Series, flagged: list[str]) -> dict:
    import shap

    X_full = encode_for_xgb(df.drop(columns=flagged, errors="ignore"))
    X_key = df[KEY_FEATURES]
    spw = float((y == 0).sum() / (y == 1).sum())
    models = make_models(spw)

    key_model = models["key18_lgbm_weighted"][1]
    key_model.fit(X_key, y)
    key_cats = {c: X_key[c].cat.categories.tolist()
                for c in X_key.select_dtypes(include="category").columns}
    with open(ARTIFACTS / "model_key18_lgbm.pkl", "wb") as f:
        pickle.dump({"model": key_model, "features": KEY_FEATURES,
                     "categories": key_cats}, f)

    full_model = models["full_xgb_weighted"][1]
    full_model.fit(X_full, y)
    with open(ARTIFACTS / "model_full_xgb.pkl", "wb") as f:
        pickle.dump({"model": full_model, "features": X_full.columns.tolist(),
                     "excluded_leakage": flagged}, f)

    # SHAP global importance on the discovery model -> the "delta" deliverable:
    # which predictive features did the model surface BEYOND the bank's 18?
    explainer = shap.TreeExplainer(full_model)
    sv = explainer.shap_values(X_full)
    imp = pd.DataFrame({
        "feature": X_full.columns,
        "mean_abs_shap": np.abs(sv).mean(axis=0),
    }).sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)
    imp["in_bank_key18"] = imp["feature"].isin(KEY_FEATURES)
    imp.to_csv(ARTIFACTS / "shap_importance_full_model.csv", index=False)

    top30 = imp.head(30)
    discovered = top30.loc[~top30["in_bank_key18"], "feature"].tolist()
    print(f"SHAP discovery: {len(discovered)} of the top-30 features are NEW "
          f"(not in the bank's 18): {discovered[:15]}")
    return {
        "top30_features": top30.to_dict(orient="records"),
        "discovered_beyond_key18": discovered,
    }


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def write_report(results: dict, discovery: dict, flagged: list[str],
                 n_splits: int, n_repeats: int) -> None:
    def fmt(s: dict) -> str:
        return f"{s['mean']:.3f} ± {s['std']:.3f} [{s['p2.5']:.3f}, {s['p97.5']:.3f}]"

    lines = [
        "# PS2 — Mule Account Classification: Results",
        "",
        f"Repeated stratified CV: **{n_splits} folds × {n_repeats} repeats** "
        f"(81 positives / 9,082 rows — a single split is meaningless).",
        f"Alert budget: **top {ALERT_BUDGET:.0%}** of accounts per fold.",
        f"Leakage audit excluded **{len(flagged)}** feature(s): "
        f"{', '.join(flagged) if flagged else '—'}.",
        "",
        "## Dataset integrity findings (state these plainly in the PDF)",
        "",
        "1. **F2230 (report month) perfectly separates the classes**: all 9,001",
        "   negatives were extracted in Oct25; all 81 positives in Sep/Nov/Dec25.",
        "   Batch membership and the label are therefore **perfectly confounded** —",
        "   any time-drifting feature can inflate performance, and this cannot be",
        "   disentangled from inside the dataset. All metrics below are upper",
        "   bounds; we recommend the bank re-extract negatives from matched windows.",
        "2. **F3912 is a near-perfect post-outcome flag** (79/81 positives = 1 vs",
        "   3/9,001 negatives) — excluded as leakage; it would deploy uselessly.",
        "3. High-index features (F3898, F3908, F3914, …) look like fraud-monitoring",
        "   alert counts — PS2's wording explicitly asks to ingest these feeds, so",
        "   they are retained as legitimate features, with the caveat above.",
        "",
        "## Cross-validated results",
        "",
        "Values are mean ± std [2.5th, 97.5th percentile] across folds.",
        "",
        "| Model | PR-AUC | ROC-AUC | Precision@1% | Recall@1% | Lift@1% |",
        "|---|---|---|---|---|---|",
    ]
    for name, m in results.items():
        lines.append(
            f"| {name} | {fmt(m['pr_auc'])} | {fmt(m['roc_auc'])} | "
            f"{fmt(m['precision_at_budget'])} | {fmt(m['recall_at_budget'])} | "
            f"{fmt(m['lift_at_budget'])} |")
    lines += [
        "",
        "## SHAP feature discovery (full model, beyond the bank's 18)",
        "",
        "New features in the SHAP top-30 not among the bank-identified 18:",
        "",
    ]
    lines += [f"- {f}" for f in discovery["discovered_beyond_key18"]]
    (ARTIFACTS / "ps2_results.md").write_text("\n".join(lines) + "\n")


# --------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quick", action="store_true",
                        help="3-fold x 1-repeat smoke test")
    args = parser.parse_args()
    n_splits, n_repeats = (3, 1) if args.quick else (5, 5)

    ARTIFACTS.mkdir(exist_ok=True)
    t0 = time.time()

    df, y = load_data()
    flagged, audit = leakage_audit(df, y)
    audit.to_csv(ARTIFACTS / "leakage_audit.csv", index=False)

    print(f"cross-validating ({n_splits}x{n_repeats})...")
    results = cross_validate(df, y, flagged, n_splits, n_repeats)

    print("fitting final models + SHAP...")
    discovery = fit_final_and_shap(df, y, flagged)

    payload = {
        "config": {"n_splits": n_splits, "n_repeats": n_repeats,
                   "alert_budget": ALERT_BUDGET, "seed": SEED,
                   "leakage_threshold": LEAKAGE_AUC_THRESHOLD},
        "leakage_flagged": flagged,
        "cv_results": results,
        "shap_discovery": discovery,
    }
    (ARTIFACTS / "metrics.json").write_text(json.dumps(payload, indent=2))
    write_report(results, discovery, flagged, n_splits, n_repeats)

    # Serving assets (thresholds.json + demo examples.json) derive from the
    # final model just written.
    import export_serving_assets
    export_serving_assets.main()

    print(f"done in {time.time() - t0:.0f}s — artifacts in {ARTIFACTS}/")
    for name, m in results.items():
        print(f"  {name}: PR-AUC {m['pr_auc']['mean']:.3f}, "
              f"P@1% {m['precision_at_budget']['mean']:.3f}, "
              f"R@1% {m['recall_at_budget']['mean']:.3f}")


if __name__ == "__main__":
    main()
