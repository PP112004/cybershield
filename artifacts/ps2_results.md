# PS2 — Mule Account Classification: Results

Repeated stratified CV: **5 folds × 5 repeats** (81 positives / 9,082 rows — a single split is meaningless).
Alert budget: **top 1%** of accounts per fold.
Leakage audit excluded **2** feature(s): F2230, F3912.

## Dataset integrity findings (state these plainly in the PDF)

1. **F2230 (report month) perfectly separates the classes**: all 9,001
   negatives were extracted in Oct25; all 81 positives in Sep/Nov/Dec25.
   Batch membership and the label are therefore **perfectly confounded** —
   any time-drifting feature can inflate performance, and this cannot be
   disentangled from inside the dataset. All metrics below are upper
   bounds; we recommend the bank re-extract negatives from matched windows.
2. **F3912 is a near-perfect post-outcome flag** (79/81 positives = 1 vs
   3/9,001 negatives) — excluded as leakage; it would deploy uselessly.
3. High-index features (F3898, F3908, F3914, …) look like fraud-monitoring
   alert counts — PS2's wording explicitly asks to ingest these feeds, so
   they are retained as legitimate features, with the caveat above.

## Cross-validated results

Values are mean ± std [2.5th, 97.5th percentile] across folds.

| Model | PR-AUC | ROC-AUC | Precision@1% | Recall@1% | Lift@1% |
|---|---|---|---|---|---|
| key18_lgbm_weighted | 0.313 ± 0.103 [0.136, 0.506] | 0.876 ± 0.050 [0.785, 0.948] | 0.287 ± 0.092 [0.111, 0.456] | 0.319 ± 0.102 [0.122, 0.512] | 32.158 ± 10.292 [12.317, 51.720] |
| key18_lgbm_smote | 0.228 ± 0.100 [0.060, 0.392] | 0.869 ± 0.046 [0.794, 0.941] | 0.247 ± 0.095 [0.056, 0.356] | 0.273 ± 0.103 [0.062, 0.390] | 27.588 ± 10.438 [6.308, 39.326] |
| full_lgbm_weighted | 0.826 ± 0.082 [0.700, 0.962] | 0.977 ± 0.018 [0.949, 0.999] | 0.716 ± 0.085 [0.556, 0.856] | 0.795 ± 0.088 [0.625, 0.939] | 80.180 ± 8.867 [63.056, 94.753] |
| full_xgb_weighted | 0.893 ± 0.057 [0.800, 0.986] | 0.981 ± 0.020 [0.950, 1.000] | 0.776 ± 0.071 [0.667, 0.911] | 0.861 ± 0.069 [0.732, 0.965] | 86.917 ± 6.982 [73.902, 97.382] |

## SHAP feature discovery (full model, beyond the bank's 18)

New features in the SHAP top-30 not among the bank-identified 18:

- F3898
- F3914
- F3908
- F3484
- F3922
- F3805
- F3841
- F3811
- F2581
- F270
- F1921
- F3534
- F3812
- F3105
- F3807
- F366
- F3873
- F3810
- F119
- F364
- F3493
- F949
- F126
- F3108
- F148
- F2029
- F1705
- F3806
- F62
- F631
