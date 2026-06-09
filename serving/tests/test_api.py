"""API tests — run from serving/ with: python3 -m pytest tests/ -v"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

EXAMPLES = json.loads(
    (Path(__file__).resolve().parents[1] / "app" / "examples.json").read_text()
) if (Path(__file__).resolve().parents[1] / "app" / "examples.json").exists() \
    else None

MOCK_TROJAN_METADATA = {
    "package_name": "com.finance.security.update.boi",
    "app_name": "Bank of India Security Update",
    "permissions": [
        "android.permission.INTERNET",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
    ],
    "suspicious_strings": [
        "http://c2-server.mulenet-control.xyz/gate.php",
        "payout to quickcash.refund@ybl",
        "8123456789:AAFakeTelegramBotTokenForTest_1234_",
    ],
}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_score_account_minimal():
    r = client.post("/score-account", json={"features": {"F115": 0.5}})
    assert r.status_code == 200
    body = r.json()
    assert 0.0 <= body["probability"] <= 1.0
    assert body["risk_band"] in ("clear", "borderline", "alert")
    assert len(body["reason_codes"]) == 5


@pytest.mark.skipif(EXAMPLES is None, reason="examples.json not built yet")
def test_examples_score_in_order():
    """The clear mule must outscore the clear legit account."""
    scores = {}
    for name, ex in EXAMPLES.items():
        r = client.post("/score-account", json={"features": ex["features"]})
        assert r.status_code == 200
        scores[name] = r.json()["probability"]
    assert scores["clear_mule"] > scores["clear_legit"]


def test_apk_metadata_analysis_deterministic():
    r = client.post("/analyze-apk/metadata",
                    json={"metadata": MOCK_TROJAN_METADATA,
                          "narrative": False})
    assert r.status_code == 200
    report = r.json()
    assert report["is_malicious"] is True
    assert report["risk_score"] >= 75  # SMS+accessibility+overlay+combo+IOCs
    assert "quickcash.refund@ybl" in report["iocs"]["upi_handle"]
    assert report["iocs"]["telegram_bot_token"]
    # determinism: same input, same score
    r2 = client.post("/analyze-apk/metadata",
                     json={"metadata": MOCK_TROJAN_METADATA,
                           "narrative": False})
    assert r2.json()["risk_score"] == report["risk_score"]


def test_apk_binary_upload_gated_off(monkeypatch):
    monkeypatch.delenv("ENABLE_APK_UPLOAD", raising=False)
    r = client.post("/analyze-apk", files={"file": ("x.apk", b"PK\x03\x04")})
    assert r.status_code == 403


def test_fusion_promotion():
    """A borderline-or-better account hitting the watchlist gets promoted."""
    r = client.post("/case", json={
        "features": MOCK_MULEISH_FEATURES,
        "beneficiaries": ["quickcash.refund@ybl"],
    })
    assert r.status_code == 200
    body = r.json()
    fused = body["fusion"]
    assert fused["watchlist_hits"], "seeded watchlist entry should match"
    if body["account_score"]["risk_band"] in ("borderline", "alert"):
        assert fused["promoted"] is True
        assert fused["final_band"] == "high-confidence alert"
    assert "case_narrative" in body and body["case_narrative"]


def test_no_watchlist_hit_no_promotion():
    r = client.post("/case", json={
        "features": MOCK_MULEISH_FEATURES,
        "beneficiaries": ["legit.merchant@okaxis"],
    })
    assert r.status_code == 200
    assert r.json()["fusion"]["promoted"] is False


MOCK_MULEISH_FEATURES = {
    "F115": 0.69, "F321": 1.31, "F527": 1.24, "F531": 1.24, "F670": 0.0,
    "F1692": 0.0, "F2082": 0.0, "F2122": 0.0036, "F2582": -0.09,
    "F2678": 0.06, "F2737": -0.27, "F2956": 191.0, "F3043": 277.0,
    "F3836": 586038.08, "F3887": 167.0, "F3889": "G365D",
    "F3891": "salaried", "F3894": 39.0,
}
