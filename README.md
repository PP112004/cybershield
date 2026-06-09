# CyberShield — APK Threat Analysis & Mule Account Detection

Solution for **BOI / PSB's Cybersecurity, Fraud & AI Hackathon 2026** (with IIT Hyderabad).
We attempt **both** problem statements as two independently complete services, plus a thin
fusion layer that the bank's own wording invites:

- **PS1 — GenAI-based automated analysis & risk scoring of fraudulent APKs.**
  Static analysis → deterministic, evidence-weighted risk score + IOC extraction
  (C2 URLs, Telegram bot tokens, beneficiary UPI handles). GenAI writes the analyst
  narrative — it **never** adjudicates the verdict.
- **PS2 — AI/ML classification of suspicious mule accounts.**
  Class-weighted gradient boosting on a 9,082 × 3,924 anonymized dataset (81 positives),
  evaluated the way a bank operates: repeated stratified CV, PR-AUC with intervals,
  precision/recall at a top-1% alert budget, SHAP reason codes per alert.
- **Fusion (PS1 → PS2).** Trojan-extracted beneficiary identifiers feed a watchlist;
  an account scoring *borderline* on the ML model that matches the watchlist is promoted
  to a high-confidence alert with a GenAI case narrative.

Full design rationale, decisions, and build plan live in **[ARCHITECTURE.md](ARCHITECTURE.md)**.

## Repository map

```
.
├── README.md                    ← you are here: how to run everything
├── ARCHITECTURE.md              ← single source of truth for every design decision
├── ps1/                         ← PS1: APK threat analysis
│   ├── apk_analyzer.py             CLI analyzer (--demo / --apk PATH / --json)
│   └── rules/                      YARA-X dex rules (4 behavioral banking-trojan rules)
├── ps2/                         ← PS2: mule account classification
│   ├── ps2_train_eval.py           reproducible train/eval (leakage audit, 5×5 CV, SHAP)
│   └── export_serving_assets.py    derives thresholds + demo examples from the model
├── serving/                     ← unified FastAPI service (PS1 + PS2 + fusion)
│   ├── app/                        endpoints, scorer, risk engine, fusion, LLM layer
│   ├── data/                       IOC watchlist (seeded; appended by the analyzer)
│   └── tests/                      API test suite (7 tests)
└── artifacts/                   ← PS2 outputs: metrics, results report, models, thresholds
```

## Setup

Python 3.12. Install everything (training + serving):

```bash
pip install -r serving/requirements.txt
pip install scikit-learn xgboost lightgbm imbalanced-learn shap pandas numpy
```

For PS2 training, place the hackathon dataset at `data/DataSet.csv`.

## Run PS2 only (mule account classification)

```bash
# reproduce metrics + models from scratch (~9 min; --quick for a smoke test)
python3 ps2/ps2_train_eval.py
```

Outputs land in `artifacts/`: `ps2_results.md` (headline table + dataset-integrity
findings), `metrics.json`, `leakage_audit.csv`, `shap_importance_full_model.csv`,
refit models, and serving thresholds. Pre-trained artifacts are committed, so the
API below works without retraining.

**Headline results (5×5 repeated stratified CV, mean):**

| Model | PR-AUC | Precision@1% | Recall@1% |
|---|---|---|---|
| key-18 features, LightGBM (class-weighted) | 0.313 | 0.287 | 0.319 |
| full-feature XGBoost (discovery model) | 0.893 | 0.776 | 0.861 |

SHAP feature discovery: the full model's entire top-30 lies **outside** the bank's
18 key features — a concrete "most relevant features" deliverable.

## Run PS1 only (APK threat analysis)

```bash
python3 ps1/apk_analyzer.py --demo            # mock banking trojan, no APK needed
python3 ps1/apk_analyzer.py --apk sample.apk  # real APK (requires androguard)
yr check ps1/rules/android_banking_behaviors.yar   # YARA-X rules (yara-x via brew)
```

The risk score is deterministic (weighted behavior rules + IOC extraction). Extracted
IOCs are pushed to the PS2 watchlist (`serving/data/watchlist.json`) — that's the fusion.

## Run both — the unified API

```bash
cd serving
uvicorn app.main:app --reload        # http://127.0.0.1:8000/docs
python3 -m pytest tests/ -v          # 7 tests
```

| Endpoint | Visibility | What it does |
|---|---|---|
| `POST /score-account` | public | PS2: 18 features → probability + SHAP reason codes |
| `POST /case` | public | fusion: ML score + watchlist promotion + case narrative |
| `POST /analyze-apk/metadata` | public | PS1: deterministic risk engine over APK metadata |
| `POST /analyze-apk` (upload) | **local only** | gated by `ENABLE_APK_UPLOAD=1` — a public malware-upload box is a liability, not a demo |
| `GET /examples`, `GET /health` | public | demo accounts / liveness |

GenAI narratives are optional: `export DEEPSEEK_API_KEY=...` (preferred) or
`GEMINI_API_KEY=...`; without a key everything falls back to deterministic templates.
See `serving/README.md` for details.

## Honest limitations (by design, stated loudly)

- **PS2 metrics are upper bounds**: the dataset's report-month field (F2230) perfectly
  confounds batch and label; a post-outcome flag (F3912) was excluded as leakage.
  Details in `artifacts/ps2_results.md`.
- **PS1 risk weights are not yet calibrated** against a labeled APK corpus; validation
  on real MalwareBazaar samples + a benign banking-app FP test is the next step.
- The provided PS2 data is anonymized, so fusion is demonstrated via the scoring API's
  watchlist input; in production the bank joins IOCs to real account identifiers.

## Data

`data/` and `docs/` are not committed: `DataSet.csv` is bank-provided hackathon data
and the PDFs are organizer material. Teammates: obtain both from the hackathon portal.
