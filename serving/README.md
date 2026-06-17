# CyberShield serving layer

FastAPI service exposing the PS2 mule-account scorer publicly, the PS1 APK
analyzer locally, and the fusion (`/case`) demo.

## Quickstart

```bash
cd serving
pip install -r requirements.txt
uvicorn app.main:app --reload --env-file .env   # http://127.0.0.1:8000/docs
```

The model artifacts are produced by `python3 ../ps2/ps2_train_eval.py`
(writes `../artifacts/model_key18_lgbm.pkl`, `thresholds.json`, and
`app/examples.json`).

## Endpoints

| Endpoint | Visibility | What it does |
|---|---|---|
| `GET /health` | public | liveness + which LLM provider is active |
| `GET /examples` | public | pre-built demo accounts (clear mule / clear legit / borderline) |
| `POST /score-account` | public | 18 key features → probability + SHAP reason codes + watchlist enrichment |
| `POST /case` | public | full fusion demo: ML score + watchlist promotion + GenAI case narrative |
| `POST /analyze-apk/metadata` | public | deterministic risk engine over pre-extracted APK metadata |
| `POST /analyze-apk` (binary upload) | **local only** | gated by `ENABLE_APK_UPLOAD=1`; disabled on hosted deployments by design — a public malware-upload endpoint is a liability, not a demo |

## GenAI configuration (optional — everything works without it)

The LLM writes narratives only; scores and verdicts are always deterministic.

Keys live in `serving/.env` (gitignored), loaded by uvicorn's `--env-file .env`:

```
DEEPSEEK_API_KEY=sk-...     # preferred (OpenAI-compatible, cheap)
# or
GEMINI_API_KEY=...
# optionally force: LLM_PROVIDER=deepseek|gemini|none
```

(Plain `export DEEPSEEK_API_KEY=...` before launching works too.)

## Tests

```bash
cd serving && python3 -m pytest tests/ -v
```
