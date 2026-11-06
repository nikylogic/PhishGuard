"""AI Guard at runtime: is this text trying to give orders to an AI?

Two layers:
  1. A small trained model (TF-IDF word + character n-grams, logistic regression).
  2. A keyword layer of classic injection phrases, as a safety net.

Long page text is split into chunks; the most suspicious chunk decides, so one
hidden sentence cannot be drowned out by a long normal article.
"""
import re
import time
from pathlib import Path

import joblib
import numpy as np

MODEL_PATH = Path(__file__).with_name("model.joblib")
THRESHOLD = 0.5
CHUNK = 400

PATTERNS = [re.compile(p, re.I) for p in (
    r"\bignore (all |any |the )?(previous|prior|above|earlier|preceding) (instructions|directives|rules|context|prompts?)",
    r"\bdisregard (all |any |the )?(previous|prior|above|earlier|your) (instructions|rules|guidelines|context)",
    r"\bforget (everything|all|your) (you were told|previous|prior|earlier|instructions)",
    r"\b(new|updated|override|overwrite) (system )?(prompt|instructions?|rules)\b",
    r"\byou are now (in )?(developer|dan|jailbreak|unrestricted)",
    r"\b(do anything now|dan mode|developer mode)\b",
    r"\b(if you are|any|dear|note to|attention|for the) (an )?(ai|llm|language model|assistant|automated)\b.{0,60}\b(say|tell|rate|mark|classify|report|ignore|approve|confirm|respond|repeat)",
    r"\b(reveal|print|output|show) (your|the) (hidden |system )?(prompt|instructions)\b",
    r"\[/?system\]|<\|?(system|im_start)\|?>",
)]


def chunks(text: str, size: int = CHUNK) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text or "")
    out, cur = [], ""
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if cur and len(cur) + len(p) + 1 > size:
            out.append(cur)
            cur = p
        else:
            cur = f"{cur} {p}".strip()
        while len(cur) > size * 2:   # one very long "sentence"
            out.append(cur[:size])
            cur = cur[size:]
    if cur:
        out.append(cur)
    return out[:60]   # 60 chunks x 400 chars covers the 8,000-char capture limit with room


class Guard:
    def __init__(self, model_path=MODEL_PATH):
        bundle = joblib.load(model_path)
        self.pipe = bundle["pipeline"]
        self.meta = bundle.get("meta", {})
        union = self.pipe.named_steps["features"]
        self._word = dict(union.transformer_list)["word"]
        self._clf = self.pipe.named_steps["clf"]
        n_word = len(self._word.vocabulary_)
        self._word_coef = self._clf.coef_[0][:n_word]
        self._word_names = self._word.get_feature_names_out()

    def model_scores(self, texts: list[str]) -> np.ndarray:
        return self.pipe.predict_proba(texts)[:, 1]

    def keyword_hits(self, text: str) -> list[str]:
        hits = []
        for p in PATTERNS:
            m = p.search(text)
            if m:
                hits.append(m.group(0)[:60])
        return hits

    def top_terms(self, text: str, k: int = 5) -> list[str]:
        x = self._word.transform([text])
        contrib = x.multiply(self._word_coef).toarray()[0]
        idx = np.argsort(contrib)[::-1][:k]
        return [self._word_names[i] for i in idx if contrib[i] > 0]

    def _worst_sentence(self, chunk: str) -> str:
        """Within the deciding chunk, find the sentence that is most clearly an injection,
        so the user is shown the exact hidden sentence, not a wall of text."""
        sents = [x.strip() for x in re.split(r"(?<=[.!?])\s+|\n+", chunk) if x.strip()]
        if len(sents) <= 1:
            return chunk
        for sent in sents:
            if self.keyword_hits(sent):
                return sent
        scores = self.model_scores(sents)
        return sents[int(np.argmax(scores))]

    def check(self, text: str) -> dict:
        """Score a text. Returns score 0..1, label, the deciding chunk and why."""
        t0 = time.perf_counter()
        parts = chunks(text)
        if not parts:
            return {"score": 0.0, "label": "clean", "chunk": "", "top_terms": [], "keywords": [], "ms": 0.0}
        scores = self.model_scores(parts)
        i = int(np.argmax(scores))
        score = float(scores[i])
        best = parts[i]
        keywords = []
        for j, p in enumerate(parts):
            hits = self.keyword_hits(p)
            if hits:
                keywords.extend(hits)
                if 0.9 > score:
                    score, best = 0.9, p
        label = "injection" if score >= THRESHOLD else "clean"
        if label == "injection":
            best = self._worst_sentence(best)
        return {
            "score": round(score, 4),
            "label": label,
            "chunk": best[:300],
            "top_terms": self.top_terms(best) if label == "injection" else [],
            "keywords": keywords[:5],
            "ms": round((time.perf_counter() - t0) * 1000, 3),
        }


_GUARD = None


def get_guard() -> Guard | None:
    """Load the model once. Returns None if the model file is missing (the app still works)."""
    global _GUARD
    if _GUARD is None and MODEL_PATH.exists():
        _GUARD = Guard()
    return _GUARD
