# Phase 4: AI Guard (prompt-injection detector)

**Goal:** a small, fast model that reads a page's text (visible and hidden) and flags sentences written to give orders to an AI assistant. When the optional LLM reviewer runs, it is told about them first.

## What was built

- `phishguard/guard/train.py` trains on three public sets plus our own web-context lines:
  - deepset/prompt-injections
  - jackhhao/jailbreak-classification
  - `phishguard/guard/data/web_context.txt`
- Duplicates that appear in both train and test were removed before training (6 rows).
- The model is TF-IDF (word 1–2 grams plus character 3–5 grams) feeding a logistic regression.
- C = 8 was chosen by 5-fold cross-validation on the training data only.
- A small keyword layer catches well-known attack phrases.
- Long pages are split into chunks, and the worst chunk decides. The UI shows the exact sentence that gave the attack away.
- `phishguard/guard/distil.py` fine-tunes DistilBERT on the same splits so the choice is backed by data.

## Results against the pass marks (set before training, see `phishguard/guard/THRESHOLDS.md`)

| Measure | Pass mark | AI Guard | Passed |
|---|---|---|---|
| F1, combined test set | ≥ 0.80 | **0.915** | yes |
| Recall, web-context test | ≥ 0.80 | **0.867** | yes |
| False-positive rate, web-context | ≤ 0.10 | **0.031** | yes |
| Average time per text | < 5 ms | **3.0 ms** (p95 8.6 ms) | yes |
| Model size | < 10 MB | **1.32 MB** | yes |

## Small model vs DistilBERT (same data, same test split)

| | AI Guard (TF-IDF + LR) | DistilBERT (3 epochs, CPU) |
|---|---|---|
| F1, combined | 0.915 | **0.938** |
| Recall, deepset | 0.60 | **0.88** |
| Recall, web-context | 0.867 | **0.967** |
| False-positive rate, web-context | **0.031** | 0.219 |
| Time per text | **3.0 ms** | 33.9 ms |
| Size | **1.32 MB** | 267.8 MB |
| Training time | **seconds** | 18 minutes |

**Decision: ship the small model.** DistilBERT catches more injections, but it wrongly flagged about 1 in 5 normal web sentences. On real pages that would put a false warning on most ordinary websites. It is also 11× slower and 200× bigger. For a tool that runs on every click, the small model is the better trade. DistilBERT is listed as a future enhancement (for example, as a second opinion only on pages the small model is unsure about).

**Honest weakness:** recall on the deepset set is only 0.60. Many of its injections are subtle or written in German, and word features miss them. The LLM reviewer and the page rules are the other layers of defence.

## Proof files

- `pytest.txt`, `junit.xml`: the Phase 4 test run (guard behaviour, chunking, pass marks re-checked from `eval.json`)
- `eval.json`, `eval_distilbert.json`: full metrics with confusion matrices
- `confusion_guard_combined.png`, `confusion_guard_web.png`, `confusion_distilbert_combined.png`
- `training-log.txt`, `training-log-distilbert.txt`
