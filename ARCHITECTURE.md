# CyberShield Hackathon — Architecture & Implementation Guide

> **Purpose of this document.** This is the single source of truth for the solution
> design and build plan for BOI's CyberShield Hackathon (PSB's Cybersecurity, Fraud &
> AI Hackathon 2026, in collaboration with IIT Hyderabad). It captures the
> first-principles architecture, the together-vs-apart decision, the data strategy,
> the demo/hosting strategy, and the sequenced build plan. Everything we implement
> should trace back to a decision recorded here. Update it when a decision changes.

**Submission deadline:** 15 June 2026 (idea-stage PDF decides shortlisting).
**Shortlist announced:** 30 June 2026. **Prototype phase:** 1 July – 17 Aug 2026.
**Final presentation:** 27–28 Aug 2026. Prize pool ₹20 L (₹5/3/2 L per topic, paid
50% finale / 30% post-GFF / 20% on product completion).

We are attempting **both** problem statements. The portal lets a team select both and
upload **one combined PDF** (no per-statement upload).

---

## 0. Guiding principles (the lens for every decision)

Design as a **senior cybersecurity / fraud specialist would for a real bank**, not as a
hackathon team optimizing for a flashy demo. Three rules fall out of that:

1. **GenAI interprets; it does not adjudicate.** Risk scores are deterministic and
   evidence-grounded. The LLM explains, summarizes, maps to frameworks, and writes
   analyst reports. This kills hallucination-as-verdict and prompt-injection attacks.
2. **Be honest about limits, loudly.** The PS2 data is anonymized; 81 positives is a
   hard statistical constraint; static analysis loses to packers. Stating these plainly
   reads as rigor to bank judges, who will spot hidden weaknesses anyway.
3. **Evaluate the way a bank operates.** Precision/recall at a fixed *alert budget*,
   false-positive rate against legitimate banking apps — not a single suspiciously
   perfect accuracy number.

---

## 1. The two problem statements (as worded on the portal)

- **PS1 — Generative AI-Based Automated Analysis and Risk Scoring of Fraudulent APKs.**
  Auto-analyze suspicious APKs: reverse engineering, malware pattern recognition,
  static + dynamic analysis, threat severity classification, risk scoring, and
  investigation reports with actionable recommendations.

- **PS2 — AI/ML-Based Classification of Suspicious Mule Accounts.** Learn behavioral /
  transactional patterns to flag mule accounts. Portal wording (important): ingest
  *"financial transactions and/or **fraud monitoring solution alerts** and/or
  transaction monitoring system alerts and **govt cyber fraud alerts/tickets**"* and
  *"consume real-time regulatory inputs/feeds."* Objective: feature-engineer to find
  the most relevant features and build a classifier separating suspicious from
  legitimate accounts.

**Key reading:** PS1's output (APK threat reports with extracted IOCs) is *literally one
of the alert feeds PS2 is asked to consume.* The integration is invited by the bank's
own wording — not a narrative we forced.

---

## 2. The together-vs-apart decision → **Modular-Unified**

**Verdict: two independently complete services + a thin shared intelligence layer.**

- **Why unify:** PS2's own text asks it to consume fraud/threat alert feeds; PS1
  produces exactly such a feed. The fusion is the standard SOC pattern of *threat-intel
  enrichment of transaction monitoring* — sound, not flashy, and recognizable to
  banking judges.
- **Why NOT a monolith:** prizes are **per-topic**, implying per-topic judging panels.
  A PS1 that only makes sense after reading PS2 would score poorly on both. So each
  service must stand alone and fully answer its own statement; the fusion bus is
  **upside, not load-bearing**.

### The technical fusion is real, not hand-waving

Indian banking trojans hardcode or fetch **beneficiary UPI handles / account numbers**
(frequently exfiltrated via Telegram bots). So:

- PS1's IOC extraction yields a **mule beneficiary watchlist**.
- PS2 consumes that watchlist as an **enrichment feature**: an account scoring
  *borderline* on the ML model but matching a trojan-extracted beneficiary is promoted
  to a **high-confidence alert**.

**Honest caveat (goes in the PDF):** the provided PS2 data is anonymized, so the
prototype demonstrates enrichment via the scoring API's watchlist input; in production
the bank joins IOCs to real account identifiers.

### System diagram

```
APK sample ──→ [PS1: APK Analysis Service] ──→ threat report, risk score
                        │ IOCs (C2s, phones, beneficiary UPI/accts)
                        ▼
              [ Intelligence Bus: watchlists, campaign clusters,
                shared GenAI case-report generator ]
                        ▲ enrichment feature        │ unified case narrative
                        │                           ▼
Txn features ─→ [PS2: Mule Scoring Service] ──→ alert + SHAP reason codes
```

---

## 3. PS1 — APK Analysis & Risk Scoring

### 3.1 Pipeline (four stages)

> Status legend used throughout: ✅ done · 🟡 partial · ⬜ not started.

1. **Triage** (cheap, kills 60–70% of the queue first): ⬜ **not started**
   - SHA-256 dedup against known samples.
   - **Signing-certificate clustering** — fraudsters reuse certs across variants;
     clustering groups a whole campaign instantly.
   - Package-name similarity to legitimate bank apps (typosquat / impersonation).
   - *(None of triage is built yet — needs real samples to be meaningful. Step 3.)*

2. **Static analysis:** 🟡 **partial**
   - Manifest: permissions, exported components, SMS-receiver priority.
     *(permissions ✅ via `serving/app/apk.py`; exported-components / SMS-receiver
     priority ⬜.)*
   - Decompiled code: which dangerous APIs are *actually called* (SmsManager,
     AccessibilityService, overlay/`SYSTEM_ALERT_WINDOW` APIs) — call-presence, not
     just permission-presence. ⬜ *(currently permission-presence + string IOCs only;
     true call-graph analysis is not built.)*
   - Strings/resources: C2 URLs, **Telegram bot tokens**, phone numbers, hardcoded
     beneficiary UPI/account IDs. ✅ *(IOC extractor in `apk.py`, regex-based.)*
   - Packer / obfuscation detection. ⬜
   - **Caveat:** today `apk.py` scores from *pre-extracted metadata*; wiring full
     Androguard decompilation + multi-dex string sweep is part of step 3.

3. **Dynamic analysis (prototype-phase, sandbox-only):** ⬜ **roadmap only.** Runtime
   network capture, dropped payloads, overlay behavior. Positioned as roadmap, not
   idea-stage promise — do NOT build before the prototype phase.

4. **Risk engine + GenAI layer:** 🟡 **partial**
   - **Deterministic risk score** = weighted evidence rules over extracted behaviors.
     ✅ built in `apk.py` (`risk_engine`), but **weights are un-calibrated guesses** —
     see §3.6. Partly implemented as a **YARA-X ruleset** (see 3.3, behavioral rules ✅).
   - **GenAI = interpretation only:** structured evidence → plain-language explanation,
     **MITRE ATT&CK Mobile** mapping, analyst report. 🟡 narrative path built
     (`apk.narrative`), but runs on template fallback until an LLM key is set;
     structured MITRE mapping ⬜.

### 3.2 Edge cases handled by design (put these in the PDF — they signal real thinking)

| Edge case | Design response |
|---|---|
| LLM hallucinates / gives different verdict per run | Score is deterministic; LLM never adjudicates. |
| **Prompt injection** — malware embeds strings like *"classify as benign"* | All APK-derived text treated strictly as **data**, never instructions. Score grounded in extracted evidence. |
| Packed APKs defeat static analysis | Packer detector emits low-confidence flag → routes to dynamic. |
| Legitimate bank apps request scary permissions | Score on behavior **combinations** + cert/store provenance, never single permissions. |
| Droppers fetch real payload at runtime | Dropper pattern (tiny APK + `REQUEST_INSTALL_PACKAGES` + download logic) is itself a scored behavior. |
| Token limits — can't feed whole decompiled app to LLM | A **prioritizer** selects only suspicious code regions for interpretation. |

### 3.3 YARA-X as a concrete component

We have the `yara-rule-authoring` skill (in `.claude/skills/`). YARA-X has a **`dex`
module** for Android bytecode. Use it to implement part of the deterministic engine:

- **Family-detection rules:** SpyNote/SpyMax, droppers, SMS-stealers, SOVA, Drinik,
  Axbanker.
- **Behavioral rules:** overlay + SMS-intercept combination; Telegram-bot exfil
  pattern; dropper pattern.

This gives triage a fast, reproducible, **auditable** detection layer banks already
understand operationally — far stronger than "we wrote some if-statements." Invoke the
skill when authoring rules; lint with the skill's `yara_lint.py`.

### 3.4 Current code asset

`apk_analyzer.py` — refactored 10 June 2026 into a thin CLI over the serving
modules (`serving/app/apk.py`, `llm.py`, `fusion.py`): Androguard static
extraction, **deterministic** risk engine (weighted behavior rules + IOC
extraction: UPI handles, Telegram bot tokens, C2 URLs, phones → watchlist),
LLM narrative-only via the swappable provider layer (DeepSeek preferred /
Gemini / template fallback). The original version let Gemini return
`is_malicious`/`risk_score` — that violated principle 1 and was removed.

### 3.5 GenAI as a performance lever in PS1 (augment the detector, never the verdict)

Beyond report-writing, GenAI improves *detection performance* in two bounded ways.
Both keep runtime adjudication fully deterministic:

1. **Offline GenAI-assisted rule synthesis (detection engineering).** The LLM reads
   decompiled code of known malicious samples and *proposes* candidate behavioral
   indicators / YARA-X rules. Proposals are validated against the reference corpus
   (must hit the family samples, zero hits on the benign set) before entering the
   deterministic engine. GenAI scales rule coverage across families faster than
   manual analysis; the runtime detector stays auditable. Demonstrate this loop on
   the real MalwareBazaar samples in step 3.
2. **Corroborated evidence extraction at runtime.** The LLM reads *selected*
   decompiled regions (token-budget prioritizer, §3.2) and flags behaviors — e.g.
   "builds an overlay targeting package X" — **with code citations**. A flag only
   contributes to the risk score if its citation verifies against the actually
   extracted strings/APIs; uncorroborated flags are reported as analyst leads, not
   scored. This catches behaviors static regexes miss (a recall gain) while
   filtering hallucinations at the corroboration step.

Explicitly rejected: LLM-in-the-scoring-loop, uncorroborated LLM features, and
runtime LLM rule generation — each turns a hallucination into a verdict.

### 3.6 PS1 evaluation gap (open — the honest weak spot, 10 June 2026)

Unlike PS2, **PS1 has no quantitative evaluation yet.** What exists are unit tests
(`serving/tests/` — "the mock trojan scores ≥75, the upload endpoint is gated") that
prove the code *runs*, not that it *discriminates*. Specifically:

- The risk-engine weights (accessibility +30, SMS +20, overlay +15, combo +20, …) are
  **intuition, not calibrated** against any ground truth.
- The YARA-X rules have **never run against a real DEX file** — only `yr check`/lint.
- We have **no detection rate** and **no false-positive rate**. §0 principle 3 demands
  exactly these; we owe them.

**What iterative improvement requires:** a labeled APK corpus → score it → measure
detection rate + FP rate (held-out split so rules aren't overfit to the corpus) →
tune weights/thresholds/rules → re-measure. The labeled set has two halves:

- **Malicious half — gated on MalwareBazaar** (or AndroZoo/CICMalDroid). Cannot be
  faked: synthetic malicious metadata is circular (tests whether our rules detect
  patterns we ourselves wrote in). This is the real blocker, needs the abuse.ch key.
- **Benign half — NOT gated.** Legitimate banking/Play apps are freely downloadable
  now (no auth). Half the labeled set can be assembled before step 3.

**Plan (added to build plan as step 2b + step 3):** write a PS1 evaluation harness now
(scaffolding — runs scorer + YARA over a labeled APK dir, emits detection rate, FP
rate, a score/PR curve, per-family breakdown); assemble the benign corpus now; then
MalwareBazaar samples close the loop and we iterate the weights against real numbers.
**Until this is done, the PDF must describe PS1 validation as *methodology*, and only
claim measured numbers for whatever corpus we actually run before 15 June.**

---

## 4. PS2 — Mule Account Classification

### 4.1 The dataset reality (drives every decision)

- 9,082 rows, 3,924 anonymized features (`F1…F3924`), target = **F3924**
  (0 legit / 1 mule).
- **81 positives (0.9%).** This number dominates everything.
- 163 columns completely empty; 600+ features >90% NA.
- 18 bank-identified key features provided: F115, F321, F527, F531, F670, F1692,
  F2082, F2122, F2582, F2678, F2737, F2956, F3043, F3836, F3887, F3889, F3891, F3894.

### 4.1b Dataset integrity findings (10 June 2026 — from the leakage audit; quote in the PDF)

1. **F2230 (report month) perfectly separates the classes**: all 9,001 negatives were
   extracted in Oct25, all 81 positives in Sep/Nov/Dec25. Batch membership and the
   label are **perfectly confounded** — any time-drifting feature can inflate
   performance, and this cannot be disentangled from inside the dataset. All reported
   metrics are therefore upper bounds; recommend the bank re-extract negatives from
   matched time windows. F2230 is excluded from modeling.
2. **F3912 is a near-perfect post-outcome flag** (79/81 positives = 1 vs 3/9,001
   negatives; single-feature AUC 0.987) — excluded as leakage.
3. High-index features (F3898, F3908, F3914, …) pattern like fraud-monitoring alert
   counts; PS2's wording explicitly asks to ingest such feeds, so they are retained,
   subject to caveat 1.

### 4.2 Design decisions

- **Evaluation:** 81 positives makes a single split meaningless (±15-pt recall swings).
  Use **repeated stratified CV**, **PR-AUC with confidence intervals**, and the metric
  banks operate on — **precision/recall at a fixed alert budget** (e.g. top 1% of
  accounts a team can review). Reporting this way *is* a differentiator; most teams
  will report a broken near-perfect accuracy.
- **Imbalance:** SMOTE in ~3,900-dim sparse space synthesizes noise. Prefer
  **class-weighted gradient boosting** (`scale_pos_weight`) + undersampling ensemble;
  SMOTE only as a compared baseline.
- **Missingness is signal:** add missingness-indicator features; don't blindly impute.
  (In bank data, "feature populated only if product/channel exists" is behavioral.)
- **Leakage audit:** with 3,924 unlabeled features, some may be post-outcome (e.g. an
  "account frozen" flag predicts perfectly, deploys uselessly). Audit and exclude any
  feature with near-perfect single-feature separation.
- **Two-model strategy** (directly answers PS2's "identify most relevant features"):
  1. **Compact interpretable model** on the 18 key features = deployable baseline.
  2. **Full-feature discovery model** whose importance/SHAP surfaces *new* predictive
     features beyond the bank's 18 — that **delta is a concrete deliverable**.
- **Explainability:** **SHAP reason codes** per alert (RBI-flavored expectation). This
  is where GenAI legitimately enters PS2 — LLM turns SHAP values + feature context into
  the analyst-readable alert narrative ("intelligent alert generation").

### 4.3 Current code assets

PS2 evaluation methodology (§4.2) is **✅ fully implemented** — repeated stratified CV,
PR-AUC + intervals, precision/recall/lift @ alert budget, leakage audit, class-weight
vs SMOTE comparison, two-model strategy, SHAP discovery delta — all in
`ps2_train_eval.py`. Code assets:

- ✅ `ps2/ps2_train_eval.py` — the reproducible train/eval (supersedes the old pickles).
  Run `python3 ps2/ps2_train_eval.py` (full 5×5, ~9 min) or `--quick` (3×1 smoke).
- ✅ `ps2/export_serving_assets.py` — writes `artifacts/thresholds.json` (alert/borderline
  bands) + `serving/app/examples.json` (demo accounts). Called at the end of a full
  train run; also runnable standalone.
- ✅ `artifacts/` — `metrics.json`, `ps2_results.md` (PDF-ready table + integrity
  findings), `leakage_audit.csv`, `shap_importance_full_model.csv`, refit models
  (`model_key18_lgbm.pkl`, `model_full_xgb.pkl`).
- ⚠️ `archive/mule_detector_*.pkl` — the original session-2 pickles. **Superseded**;
  kept only for reference (archive/ is not committed). Serving loads the new
  `artifacts/model_key18_lgbm.pkl`.
- ✅ `serving/app/meta.json` — feature schema for the serving layer.
- ✅ `serving/` — full FastAPI service (score/case/analyze-apk, 7/7 tests pass).

**PS2 iterative-improvement levers still open (all doable now, no external data):**
probability calibration, alert-threshold tuning, feature selection off the SHAP
ranking, an undersampling ensemble (§4.2 mentions it; not yet built), and an honest
"with vs without the high-index alert-count features" ablation given the §4.1b confound.

### 4.4 GenAI as a performance lever in PS2 (new signal, not a re-weighted scorer)

**Honest position (state it in the PDF):** on the provided anonymized dataset, GenAI
cannot improve classifier performance. LLM value on tabular data is domain priors,
and anonymized `F…` names sever them; LLM-synthesized rows in a ~3,900-dim
anonymized space are noise (our CV already shows even SMOTE loses to plain class
weighting). Claiming "LLM-boosted accuracy" here would be vapor, and bank judges
would spot it.

Where GenAI *does* raise system-level performance — by creating signal that doesn't
exist today:

1. **Unstructured alert/ticket parsing (production roadmap, the strongest claim).**
   PS2's own wording asks to ingest *"govt cyber fraud alerts/tickets"* — NCRP/I4C
   tickets are free text. An LLM extracts structured fields (flagged account/UPI
   identifiers, modus operandi, amounts, beneficiary chains) that become **new
   classifier features and watchlist entries**. Direct performance contribution via
   new inputs; not demonstrable on the anonymized CSV, so it is prototype-phase
   scope with that caveat stated.
2. **The PS1→PS2 watchlist (built).** Trojan-extracted beneficiaries promoting
   borderline accounts is a recall gain at the alert budget for the *alerting
   system*, with GenAI upstream in producing threat reports at scale.

Explicitly rejected: LLM in the scoring loop and LLM-generated synthetic training
data.

---

## 5. Data strategy

### 5.1 PS2 — already provided

`DataSet.csv` is in hand. No acquisition problem. Work is rigor (4.2), not collection.

### 5.2 PS1 — no data provided; here's how we get around it

**Framing:** PS1 is NOT a "train on 100k samples" problem. The engine is
evidence/rule-based + LLM interpretation, so we need a **curated, well-provenanced
reference set** — a few hundred samples total — for three jobs: (a) develop/validate
rules & heuristics, (b) calibrate the risk score, (c) measure false positives against
legitimate apps.

**Malicious samples (priority order):**

1. **MalwareBazaar (abuse.ch)** — the workhorse. Free, instant API, tag-searchable. Has
   the actual India-targeting campaigns: SpyNote/SpyMax, **Drinik** (income-tax themed),
   **SOVA**, **Axbanker**, the "rewards APK" smishing wave. Using PSB-targeting samples
   is a detail BOI judges will feel. Samples ship as password-protected zips
   (password: `infected`).
2. **AndroZoo** — millions of APKs + VirusTotal counts; free for research but needs an
   access request with an academic email (**apply now**, approval takes days).
3. **Academic labeled sets** — CICMalDroid 2020, Drebin — citable benchmarks (Drebin is
   dated but quotable).

**Benign samples (equally important — most teams forget):** legitimate Indian banking
apps (BOI Mobile, YONO, iMobile, BHIM) from APKMirror/APKPure + top Play Store apps +
F-Droid. **The hard false-positive test:** real banking apps request SMS/overlay
permissions. If the scorer flags BOI's own app as malware, the demo dies in front of
the one audience guaranteed to try it. Report FP rate against this benign set.
**Note (10 June 2026):** the benign half is **not gated on any signup** — it can be
collected immediately, independent of the abuse.ch key. Do this early; it's half the
PS1 evaluation corpus (§3.6).

**Handling procedure — treat samples as live weapons:**

- Keep samples in password-protected zips at rest; never leave bare APKs in a
  synced/indexed folder.
- **Static analysis on host only, carefully** — parsing ≠ executing, but decompilers
  have had CVEs; run analysis in an isolated working dir, non-privileged; never
  auto-render samples.
- **Dynamic analysis only in a disposable emulator** with no/filtered network
  (prototype-phase scope).
- **Never on a personal phone.**
- **Provenance manifest per sample:** SHA-256, source, family tag, first-seen date →
  becomes the PDF's "dataset description" and makes every metric auditable.

**For the 15 June PDF:** we do NOT need the full corpus — we need to *name* the sources,
the curation criteria (India-targeting campaigns + matched benign set), and the
validation methodology (detection rate on known families, FP rate on legit banking
apps). Grabbing ~20 MalwareBazaar samples before the demo lets us validate end-to-end on
real malware rather than only the mock.

---

## 6. Demo & proof-of-work strategy

**Goal:** the strongest idea-stage sentence is *"this already runs — here's the link and
the repo."* Building the end-to-end loop now also **de-risks the fusion claim** before
the July prototype phase (when 50% of prize money rides on the progress report).

**The two PS fail very differently — so they get different demo treatment:**

- **PS2 → host publicly (safe).** FastAPI `/score-account` takes a feature vector →
  probability + SHAP reason codes. Deterministic, no security surface, free-tier
  hostable. *Caveat:* inputs are anonymized `F…` features, so a judge can't hand-craft a
  meaningful account → demo via **pre-built example accounts** (clear mule / clear legit
  / borderline) that score live with explanations.

- **PS1 → DO NOT host a public upload endpoint.** A public `/analyze-apk` that accepts
  arbitrary binary uploads is a malware-upload service run on the open internet — a real
  liability, and abuse makes the link a **mark against us** with a bank-security panel.
  Show the same proof two safer ways:
  1. **Recorded walkthrough / screenshots** in the PDF of the analyzer running on a real
     MalwareBazaar sample (e.g. a SpyNote variant) producing the threat report.
  2. **Public, locally-runnable repo** — the hosted interactive endpoint is **PS2 only**;
     judges verify PS1 in their own sandbox (a security judge respects this *more* than
     a public upload box).

**Hosting decision:** *(open — leaning Hugging Face Spaces for the ML stack; build the
FastAPI app host-agnostic so the deploy target can be chosen at PDF-finalization time.)*

---

## 7. Build plan (sequenced)

> Rationale for order: the PDF decides shortlisting and nothing else is judged before
> 30 June — but we want the PDF to quote **real numbers** and link a **live demo**, so
> the metrics + service come first, PDF last.

1. ✅ **DONE — PS2 reproducible train/eval script** → real metrics (repeated stratified
   CV, PR-AUC + CI, precision/recall @ alert budget, leakage audit, two-model strategy
   with SHAP feature-discovery delta). `ps2_train_eval.py` + `export_serving_assets.py`.
2. ✅ **DONE — FastAPI service:**
   - ✅ `/score-account` — live, public (PS2): vector → prob + SHAP reason codes.
   - ✅ `/analyze-apk` (local-only, gated) + `/analyze-apk/metadata` (PS1).
   - ✅ `/case` — the **fusion** (IOC watchlist enrichment → promoted alert + narrative).
   - 7/7 tests pass; LLM provider swappable (DeepSeek/Gemini/template fallback).
2b. ⬜ **TODO (next, no external data needed) — PS1 evaluation harness + benign corpus.**
   Write the harness (scorer + YARA over a labeled APK dir → detection rate, FP rate,
   score/PR curve, per-family breakdown — §3.6). Assemble the benign corpus (BOI Mobile,
   YONO, BHIM, top Play apps). This unblocks PS1 iterative tuning the moment samples land.
   *Also small serving upgrades to do alongside once a DeepSeek key is set: LLM alert
   narratives on `/score-account`, structured MITRE mapping in the PS1 report.*
3. ⬜ **TODO (gated on abuse.ch key) — Run PS1 on ~20 real MalwareBazaar samples.**
   Capture walkthrough/screenshots; run the §2b harness for real detection/FP numbers;
   demonstrate the §3.5 GenAI rule-synthesis loop on one family (LLM proposes indicators
   from decompiled code → corpus-validated → rule admitted).
4. 🟡 **PARTIAL — Author YARA-X dex rules.** ✅ Behavioral rules done
   (`ps1/rules/android_banking_behaviors.yar`, 4 rules, linted). ⬜ Family rules
   (SpyNote/SpyMax, Drinik, SOVA, Axbanker) wait for real samples — step 3.
5. ⬜ **TODO (last, deadline 15 June) — Write the PDF** — three sections:
   - **Section A:** complete PS1 solution (pipeline, edge-cases/threat-model, YARA,
     data strategy, validation **methodology** — measured numbers only for the corpus
     actually run, per §3.6).
   - **Section B:** complete PS2 solution (data reality + §4.1b integrity findings,
     evaluation methodology, real metrics from `artifacts/ps2_results.md`, two-model
     strategy, explainability).
   - **Section C (short):** the integration layer as prototype-phase vision, anonymized-
     data caveat stated plainly.
   - Plus: architecture diagrams, July–Aug prototype roadmap, links to live demo + repo.

---

## 8. Open decisions / parking lot

- [ ] **Hosting target** for public PS2 demo (HF Spaces vs Render/Railway vs local+ngrok
      vs decide-later). Build host-agnostic until chosen. *(Service is host-agnostic ✅;
      decision still open — make it at PDF-finalization.)*
- [x] ~~**Build mode for serving layer**~~ — **resolved 10 June**: ship mode for this
      build (user's explicit choice). Coach mode remains the folder default for future
      sessions unless toggled.
- [ ] **Get the abuse.ch / MalwareBazaar auth key** (free signup at auth.abuse.ch) —
      the gate on step 3's malicious samples. **Do this before next session.**
- [ ] Apply for **AndroZoo** access now (academic email, multi-day approval) — backup
      malicious source.
- [ ] **Set `DEEPSEEK_API_KEY`** in the environment to activate LLM narratives (preferred
      over Gemini per user; both work). Optional until step 3 walkthrough.
- [ ] Resolve college-ID upload bug (Safari triggers download instead of upload) or use
      an alternate browser / submission path.
- [ ] Align teammates on the modular-unified narrative.

---

## 9. Status snapshot & session handoff (updated 10 June 2026, evening)

### 9.1 Done this session (✅)
- **Step 1 — PS2 train/eval** (`ps2_train_eval.py`): leakage audit caught the F2230
  batch confound + F3912 post-outcome flag (§4.1b); 5×5 repeated stratified CV.
  **Real metrics:** key18 LGBM weighted PR-AUC 0.313 / P@1% 0.287 / R@1% 0.319;
  full-feature XGB PR-AUC 0.893 / P@1% 0.776 / R@1% 0.861; SMOTE loses to class
  weighting on both. SHAP discovery: the full model's entire top-30 sits outside the
  bank's 18 — the delta deliverable is real.
- **Step 2 — `serving/` FastAPI service:** `/score-account`, `/case`, `/analyze-apk`
  (gated) + `/analyze-apk/metadata`, `/health`, `/examples`. SHAP reason codes via
  native LightGBM `pred_contrib` (no shap dep at serve time). LLM layer swappable
  (`serving/app/llm.py`: DeepSeek preferred / Gemini / template fallback). **7/7 tests
  pass.** Server boots; `/case` promotion demo verified live.
- **Step 4 (partial) — YARA-X:** `ps1/rules/android_banking_behaviors.yar` — 4 behavioral
  dex rules, pass `yr check`/`yr fmt`/skill lint. yara-x 1.17.0 installed (brew).
- **Refactor:** `apk_analyzer.py` is now a thin CLI over the serving modules; removed
  the LLM-adjudicates-verdict anti-pattern (principle 1).
- **Docs:** ARCHITECTURE.md §3.1/§3.4/§3.5/§3.6/§4.1b/§4.3/§4.4 updated; MEMORY.md
  Session 3 logged.

### 9.2 File inventory (what lives where — restructured 10 June 2026 for GitHub)
```
README.md                    one-stop repo guide (PS1-only / PS2-only / both)
ps2/ps2_train_eval.py        PS2 train/eval (run this to regenerate metrics+models)
ps2/export_serving_assets.py thresholds.json + examples.json (auto-run by train)
ps1/apk_analyzer.py          PS1 CLI (--demo / --apk PATH / --json)
ps1/rules/android_banking_behaviors.yar   4 behavioral YARA-X dex rules
artifacts/                   metrics.json, ps2_results.md, leakage_audit.csv,
                             shap_importance_full_model.csv, model_*.pkl, thresholds.json
data/DataSet.csv             bank dataset (gitignored, NOT pushed)
docs/                        hackathon manual, Topic.pdf, bug-report mail (gitignored)
archive/                     superseded session-2 pickles, app_meta.json (gitignored)
serving/app/
  main.py        FastAPI app (endpoints)
  scoring.py     PS2 scorer + SHAP reason codes
  apk.py         PS1 deterministic risk engine + IOC extraction
  fusion.py      watchlist + promotion + case narrative
  llm.py         DeepSeek/Gemini/none provider abstraction
  meta.json      feature schema      examples.json  demo accounts
serving/data/watchlist.json  IOC watchlist (seeded; appended by analyzer)
serving/tests/test_api.py    7 tests   conftest.py  temp-watchlist isolation
```

### 9.3 How to run (next session quick-start; all from the repo root)
```bash
# regenerate PS2 metrics + models (~9 min; or add --quick for a 3×1 smoke test)
python3 ps2/ps2_train_eval.py
# serve
cd serving && pip install -r requirements.txt && uvicorn app.main:app --reload
# tests
cd serving && python3 -m pytest tests/ -v
# PS1 CLI
python3 ps1/apk_analyzer.py --demo
# YARA
yr check ps1/rules/android_banking_behaviors.yar
# activate LLM narratives (optional)
export DEEPSEEK_API_KEY=sk-...      # or GEMINI_API_KEY=...
```
Env: pyenv Python 3.12.13; sklearn 1.8.0 / xgboost 3.2.0 / lightgbm 4.6.0 (match the
pickles); shap, fastapi, uvicorn, httpx, python-multipart, pytest installed.

### 9.4 Pick up here next session (ordered)
1. **Before the session:** get the **abuse.ch auth key** (auth.abuse.ch) and, if you
   want live LLM narratives, have a **DeepSeek key** ready.
2. **Step 2b (no blockers):** build the **PS1 evaluation harness** (§3.6) + start the
   **benign APK corpus** (not gated). Optionally add LLM alert narratives to
   `/score-account` + structured MITRE mapping (needs the DeepSeek key).
3. **Step 3 (needs abuse.ch key):** pull ~20 MalwareBazaar samples → run the harness for
   real detection/FP numbers → tune the risk weights → demonstrate the §3.5 rule-
   synthesis loop → capture walkthrough screenshots → author family YARA rules.
4. **Step 5:** write the **PDF** (deadline **15 June**) from `artifacts/ps2_results.md`
   + the §4.1b findings + the PS1 methodology. Decide hosting at finalization.

### 9.5 Known honest weak spots to keep visible
- PS1 risk weights are **un-calibrated** until step 3 runs the harness (§3.6).
- PS2 metrics are **upper bounds** due to the F2230 batch confound (§4.1b).
- PS1 static analysis currently scores from pre-extracted metadata; full decompilation
  + call-graph analysis is not yet wired (§3.1 stage 2).
