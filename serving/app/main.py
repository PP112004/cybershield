"""CyberShield serving layer — three endpoints, per ARCHITECTURE.md §6/§7:

  POST /score-account  (PS2, public)      vector -> probability + SHAP reason
                                          codes + optional watchlist enrichment
  POST /analyze-apk    (PS1, LOCAL ONLY)  gated by ENABLE_APK_UPLOAD=1; a
                                          public malware-upload box is a
                                          liability, not a demo
  POST /case           (fusion)           account + beneficiaries [+ APK
                                          report] -> promoted alert + unified
                                          GenAI case narrative

Run:  uvicorn app.main:app --reload   (from the serving/ directory)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile
from pydantic import BaseModel, Field

from . import apk, fusion
from .scoring import Scorer

app = FastAPI(
    title="CyberShield — APK Threat Analysis & Mule Account Scoring",
    description="PS1 + PS2 services with a thin shared intelligence layer. "
                "Deterministic scoring; GenAI interprets, never adjudicates.",
    version="0.1.0",
)

scorer = Scorer()

EXAMPLES_PATH = Path(__file__).resolve().parent / "examples.json"


class ScoreRequest(BaseModel):
    features: dict = Field(
        ..., description="The 18 key features (F115 ... F3894); missing "
                         "values are allowed and handled natively.")
    beneficiaries: list[str] = Field(
        default_factory=list,
        description="Outbound beneficiary identifiers (UPI handles, phones) "
                    "to check against the trojan-extracted watchlist.")


class ApkMetadataRequest(BaseModel):
    metadata: dict = Field(
        ..., description="Pre-extracted APK metadata (package_name, "
                         "permissions, suspicious_strings, ...). Lets the "
                         "pipeline run where androguard is unavailable.")
    narrative: bool = True


class CaseRequest(BaseModel):
    features: dict
    beneficiaries: list[str] = Field(default_factory=list)
    apk_report: dict | None = Field(
        default=None, description="A threat report from /analyze-apk to "
                                  "fuse into the case.")


@app.get("/health")
def health() -> dict:
    from . import llm
    return {"status": "ok", "model": "key18_lgbm_weighted",
            "llm_provider": llm.provider()}


@app.get("/examples")
def examples() -> dict:
    """Pre-built demo accounts (clear mule / clear legit / borderline) —
    inputs are anonymized F-features, so judges score these live instead of
    hand-crafting vectors."""
    if EXAMPLES_PATH.exists():
        return json.loads(EXAMPLES_PATH.read_text())
    raise HTTPException(404, "examples.json not generated yet "
                             "(run ps2_train_eval.py)")


def _score_or_422(features: dict) -> dict:
    """Scoring can raise on malformed feature values; surface a clean 422
    rather than a 500 with a traceback that leaks internals."""
    try:
        return scorer.score(features)
    except Exception as exc:
        raise HTTPException(422, f"could not score account: {exc}") from exc


@app.post("/score-account")
def score_account(req: ScoreRequest) -> dict:
    result = _score_or_422(req.features)
    hits = fusion.check(req.beneficiaries) if req.beneficiaries else []
    result["fusion"] = fusion.fuse(result, hits)
    return result


@app.post("/analyze-apk/metadata")
def analyze_apk_metadata(req: ApkMetadataRequest) -> dict:
    """Analyze pre-extracted metadata (no binary handling).

    This endpoint is public, so by design it is READ-ONLY: it never mutates the
    shared watchlist that /case adjudicates on. Persisting attacker-controlled
    IOCs from a public input would let anyone poison the watchlist and trigger
    false high-confidence alerts on legitimate accounts. The extracted IOCs are
    returned as candidates; an operator persists them only via a trusted,
    locally-gated path (ENABLE_WATCHLIST_WRITE=1, or the binary /analyze-apk)."""
    report = apk.risk_engine(req.metadata)
    if os.environ.get("ENABLE_WATCHLIST_WRITE") == "1":
        report["watchlist_iocs_added"] = fusion.add_iocs(
            report["iocs"], source=report["package_name"] or "unknown")
    else:
        report["watchlist_iocs_added"] = 0
        report["candidate_iocs"] = report["iocs"]
    if req.narrative:
        report["analyst_narrative"] = apk.narrative(report)
    return report


@app.post("/analyze-apk")
async def analyze_apk(file: UploadFile) -> dict:
    """APK binary upload — DISABLED unless ENABLE_APK_UPLOAD=1 (local use).
    The hosted demo exposes PS2 only; PS1 runs in the judge's own sandbox."""
    if os.environ.get("ENABLE_APK_UPLOAD") != "1":
        raise HTTPException(
            403,
            "APK upload is disabled on hosted deployments by design: a "
            "public endpoint accepting arbitrary binaries is a malware-"
            "upload service. Run locally with ENABLE_APK_UPLOAD=1, or use "
            "/analyze-apk/metadata.")
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=True) as tmp:
        tmp.write(await file.read())
        tmp.flush()
        metadata = apk.extract_metadata(tmp.name)
    report = apk.risk_engine(metadata)
    report["watchlist_iocs_added"] = fusion.add_iocs(
        report["iocs"], source=report["package_name"] or "unknown")
    report["analyst_narrative"] = apk.narrative(report)
    return report


@app.post("/case")
def case(req: CaseRequest) -> dict:
    """The fusion demo: ML score + watchlist enrichment + unified narrative."""
    score_result = _score_or_422(req.features)
    hits = fusion.check(req.beneficiaries) if req.beneficiaries else []
    fusion_result = fusion.fuse(score_result, hits)
    return {
        "account_score": score_result,
        "fusion": fusion_result,
        "apk_report_attached": req.apk_report is not None,
        "case_narrative": fusion.case_narrative(
            score_result, fusion_result, req.apk_report),
    }
