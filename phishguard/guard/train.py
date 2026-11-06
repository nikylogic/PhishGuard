"""Train and evaluate the AI Guard model.

    python -m phishguard.guard.train

1. Download the two public datasets (Apache-2.0) into guard_work/raw (once).
2. Build train and test sets, plus our web-context set split in half.
3. Choose C by 5-fold cross-validation on the training set only.
4. Evaluate once on the held-out test set; write eval.json and confusion matrices.
"""
import json
import random
import time
import urllib.request
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, accuracy_score
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.pipeline import FeatureUnion, Pipeline

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RAW = ROOT / "guard_work" / "raw"
PROOF = ROOT / "proof" / "phase-4"
HF = "https://huggingface.co/datasets"
SOURCES = {
    "deepset_train.parquet": f"{HF}/deepset/prompt-injections/resolve/main/data/train-00000-of-00001-9564e8b05b4757ab.parquet",
    "deepset_test.parquet": f"{HF}/deepset/prompt-injections/resolve/main/data/test-00000-of-00001-701d16158af87368.parquet",
    "jb_train.csv": f"{HF}/jackhhao/jailbreak-classification/resolve/main/default/jailbreak_dataset_train.csv",
    "jb_test.csv": f"{HF}/jackhhao/jailbreak-classification/resolve/main/default/jailbreak_dataset_test.csv",
}


def download():
    RAW.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        if not (RAW / name).exists():
            urllib.request.urlretrieve(url, RAW / name)


def norm(t: str) -> str:
    return " ".join(str(t).lower().split())


def load_splits() -> tuple[pd.DataFrame, pd.DataFrame]:
    download()
    tr = [pd.read_parquet(RAW / "deepset_train.parquet").assign(source="deepset")]
    te = [pd.read_parquet(RAW / "deepset_test.parquet").assign(source="deepset")]
    for name, bucket in (("jb_train.csv", tr), ("jb_test.csv", te)):
        d = pd.read_csv(RAW / name)
        bucket.append(pd.DataFrame({"text": d["prompt"], "label": (d["type"] == "jailbreak").astype(int),
                                    "source": "jailbreak"}))
    # Web-context set: every line is used once; alternate lines go to train and test,
    # separately for each label, with a fixed shuffle so the split is reproducible.
    rows = []
    for line in (HERE / "data" / "web_context.txt").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            lab, txt = line.split("\t", 1)
            rows.append((txt, int(lab)))
    rng = random.Random(42)
    web_tr, web_te = [], []
    for lab in (0, 1):
        items = [r for r in rows if r[1] == lab]
        rng.shuffle(items)
        web_tr += items[0::2]
        web_te += items[1::2]
    tr.append(pd.DataFrame(web_tr, columns=["text", "label"]).assign(source="web"))
    te.append(pd.DataFrame(web_te, columns=["text", "label"]).assign(source="web"))
    train, test = pd.concat(tr, ignore_index=True), pd.concat(te, ignore_index=True)
    train = train.dropna(subset=["text"]).drop_duplicates(subset=["text"])
    test = test.dropna(subset=["text"]).drop_duplicates(subset=["text"])
    # No test text may also appear in training (exact match after normalising).
    seen = set(train["text"].map(norm))
    leaked = test["text"].map(norm).isin(seen)
    test = test[~leaked].reset_index(drop=True)
    return train.reset_index(drop=True), test, int(leaked.sum())


def build_pipeline(C=4.0) -> Pipeline:
    features = FeatureUnion([
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2, sublinear_tf=True,
                                 max_features=40000, lowercase=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True,
                                 max_features=60000, lowercase=True)),
    ])
    clf = LogisticRegression(C=C, class_weight="balanced", max_iter=3000, solver="liblinear")
    return Pipeline([("features", features), ("clf", clf)])


def metrics(y, p) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "accuracy": round(accuracy_score(y, p), 4),
            "precision": round(precision_score(y, p, zero_division=0), 4),
            "recall": round(recall_score(y, p, zero_division=0), 4),
            "f1": round(f1_score(y, p, zero_division=0), 4),
            "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}


def plot_confusion(cm: dict, title: str, path: Path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    m = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    fig, ax = plt.subplots(figsize=(4.2, 3.8), dpi=200)
    ax.imshow(m, cmap="Blues")
    for (i, j), v in np.ndenumerate(m):
        ax.text(j, i, str(v), ha="center", va="center", fontsize=15,
                color="white" if v > m.max() / 2 else "#0f2a5c")
    ax.set_xticks([0, 1], ["clean", "injection"])
    ax.set_yticks([0, 1], ["clean", "injection"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title, fontsize=10)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def evaluate(predict, test: pd.DataFrame) -> dict:
    p = predict(test["text"].tolist())
    out = {"combined": metrics(test["label"], p)}
    for src, g in test.groupby("source"):
        out[src] = metrics(g["label"], p[g.index])
    return out


def main():
    PROOF.mkdir(parents=True, exist_ok=True)
    train, test, leaked = load_splits()
    log = [f"train rows: {len(train)} (injections {int(train.label.sum())})",
           f"test rows: {len(test)} (injections {int(test.label.sum())})",
           f"test rows removed because the same text was in training: {leaked}"]

    t0 = time.time()
    search = GridSearchCV(build_pipeline(), {"clf__C": [0.5, 2.0, 8.0, 32.0]}, scoring="f1",
                          cv=StratifiedKFold(5, shuffle=True, random_state=42), n_jobs=-1)
    search.fit(train["text"], train["label"])
    pipe = search.best_estimator_
    log.append(f"cross-validation F1 by C: " + ", ".join(
        f"C={c}: {s:.3f}" for c, s in zip(search.cv_results_["param_clf__C"], search.cv_results_["mean_test_score"])))
    log.append(f"chosen C = {search.best_params_['clf__C']} (training took {time.time() - t0:.1f} s)")

    model_path = HERE / "model.joblib"
    joblib.dump({"pipeline": pipe, "meta": {"C": search.best_params_["clf__C"], "train_rows": len(train)}},
                model_path, compress=3)

    from .guard import Guard
    g = Guard(model_path)
    model_only = evaluate(lambda xs: (g.model_scores(xs) >= 0.5).astype(int), test)

    times = []

    def full_guard(xs):
        out = []
        for x in xs:
            r = g.check(x)
            times.append(r["ms"])
            out.append(1 if r["label"] == "injection" else 0)
        return np.array(out)

    guard_eval = evaluate(full_guard, test)
    size_mb = model_path.stat().st_size / 1e6
    result = {
        "model": "TF-IDF (word 1-2 + char 3-5 grams) + logistic regression",
        "chosen_C": search.best_params_["clf__C"],
        "train_rows": len(train), "test_rows": len(test), "leaked_rows_removed": leaked,
        "model_only": model_only, "guard_with_keywords": guard_eval,
        "latency_ms": {"mean": round(float(np.mean(times)), 3), "p95": round(float(np.percentile(times, 95)), 3)},
        "model_size_mb": round(size_mb, 2),
    }
    (PROOF / "eval.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    plot_confusion(guard_eval["combined"]["confusion"], "AI Guard (model + keywords): combined test set",
                   PROOF / "confusion_guard_combined.png")
    plot_confusion(guard_eval["web"]["confusion"], "AI Guard: web-context test half",
                   PROOF / "confusion_guard_web.png")
    (PROOF / "training-log.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    print("\n".join(log))
    print(json.dumps({k: result[k] for k in ("chosen_C", "latency_ms", "model_size_mb")}))
    for name in ("model_only", "guard_with_keywords"):
        for src, m in result[name].items():
            print(f"{name:20s} {src:10s} F1={m['f1']:.3f} P={m['precision']:.3f} R={m['recall']:.3f} FPR={m['false_positive_rate']:.3f} n={m['n']}")


if __name__ == "__main__":
    main()
