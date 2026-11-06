"""Comparison model for the report: DistilBERT fine-tuned on the same data, on CPU.

    python -m phishguard.guard.distil

It is NOT shipped with PhishGuard (PyTorch alone is hundreds of MB). It exists to
answer a fair question in the report: how much does a transformer gain over the
small model, and what does that gain cost in speed and size?
"""
import json
import time
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from .train import PROOF, ROOT, evaluate, load_splits, plot_confusion

NAME = "distilbert-base-uncased"
MAX_LEN = 128
EPOCHS = 3
BATCH = 16
LR = 5e-5
OUT = ROOT / "guard_work" / "distilbert"


def main():
    torch.manual_seed(42)
    torch.set_num_threads(max(1, torch.get_num_threads()))
    train, test, _ = load_splits()
    tok = AutoTokenizer.from_pretrained(NAME)
    model = AutoModelForSequenceClassification.from_pretrained(NAME, num_labels=2)

    enc = tok(train["text"].tolist(), truncation=True, max_length=MAX_LEN, padding="max_length", return_tensors="pt")
    labels = torch.tensor(train["label"].values)
    ds = list(zip(enc["input_ids"], enc["attention_mask"], labels))
    loader = DataLoader(ds, batch_size=BATCH, shuffle=True)
    # Same class balance idea as the small model: weight the rarer class up.
    pos = float(labels.sum())
    weights = torch.tensor([1.0, (len(labels) - pos) / pos])
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights)
    opt = torch.optim.AdamW(model.parameters(), lr=LR)

    log, t0 = [], time.time()
    model.train()
    for epoch in range(EPOCHS):
        total = 0.0
        for ids, mask, y in loader:
            opt.zero_grad()
            out = model(input_ids=ids, attention_mask=mask)
            loss = loss_fn(out.logits, y)
            loss.backward()
            opt.step()
            total += loss.item()
        msg = f"epoch {epoch + 1}: mean loss {total / len(loader):.4f} ({time.time() - t0:.0f} s so far)"
        print(msg, flush=True)
        log.append(msg)
    train_secs = time.time() - t0

    model.eval()
    times = []

    @torch.no_grad()
    def predict(texts):
        preds = []
        for t in texts:
            s = time.perf_counter()
            e = tok([t], truncation=True, max_length=MAX_LEN, return_tensors="pt")
            p = int(model(**e).logits.argmax(-1))
            times.append((time.perf_counter() - s) * 1000)
            preds.append(p)
        return np.array(preds)

    res = evaluate(predict, test)
    OUT.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(OUT)
    size_mb = sum(f.stat().st_size for f in OUT.glob("*") if f.is_file()) / 1e6
    result = {"model": NAME, "epochs": EPOCHS, "max_len": MAX_LEN, "train_seconds": round(train_secs, 1),
              "eval": res, "latency_ms": {"mean": round(float(np.mean(times)), 2),
                                          "p95": round(float(np.percentile(times, 95)), 2)},
              "model_size_mb": round(size_mb, 1)}
    (PROOF / "eval_distilbert.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (PROOF / "training-log-distilbert.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    plot_confusion(res["combined"]["confusion"], "DistilBERT: combined test set", PROOF / "confusion_distilbert_combined.png")
    for src, m in res.items():
        print(f"distilbert {src:10s} F1={m['f1']:.3f} P={m['precision']:.3f} R={m['recall']:.3f} FPR={m['false_positive_rate']:.3f}")
    print(json.dumps({k: result[k] for k in ("train_seconds", "latency_ms", "model_size_mb")}))


if __name__ == "__main__":
    main()
