# AI Guard: pass marks, written BEFORE training

These targets were written down before any model was trained or tested, so the results can't be bent to fit them afterwards. (git history shows this file was committed before `eval.json` existed.)

The test data is never used for training or for choosing settings. Settings (the regularisation strength C) are chosen by 5-fold cross-validation on the training data only.

| Measure | On what | Pass mark |
|---|---|---|
| F1 score (injection class) | combined held-out test set (deepset + jailbreak-classification + web-context) | ≥ 0.80 |
| Recall (injections caught) | web-context test half (what PhishGuard actually sees) | ≥ 0.80 |
| False-positive rate (normal text flagged) | web-context test half | ≤ 0.10 |
| Average time per text | the whole combined test set, one text at a time, on this laptop | < 5 ms |
| Model file size | `model.joblib` | < 10 MB |

**Why these numbers:** the deepset test set is known to be hard. It includes German text and subtle injections, and simple models usually score in the 0.7–0.8 range on it. The combined target of 0.80 is realistic, not flattering. The web-context targets matter most, because that's PhishGuard's real job.

If a pass mark is missed, the report says so honestly. Thresholds are not changed after the results are seen.
