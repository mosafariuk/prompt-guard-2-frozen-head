"""On-prem injection-classifier for the deep-scan tier (paper §IX / Phase 5a).

Two modes:
  - NATIVE (default): the model's own sequence-classification head (softmax over
    logits). This is Meta Prompt Guard 2's precision-first head (OOD recall ~22.8%).
  - COMPOSED HEAD (HEAD_PATH set): PG2's frozen encoder + ContextPooler -> a custom
    logistic-regression head (numpy weights) -> calibrated threshold. This is the
    Phase-5a-ter result: OOD recall 99.9% @ 0.7% FPR (validated on fresh disjoint
    data). Inference is sigmoid(pooled . coef + intercept) >= threshold — no sklearn
    at serve time. Set HEAD_PATH=/models/head.npz to activate.
"""
from __future__ import annotations
import os
import time
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

MODEL_ID = os.environ.get("MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "512"))
DEVICE = os.environ.get("DEVICE") or ("cuda" if torch.cuda.is_available() else "cpu")
HEAD_PATH = os.environ.get("HEAD_PATH")  # e.g. /models/head.npz
_POSITIVE = {"malicious", "injection", "jailbreak", "label_1", "1", "unsafe", "inj"}


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + np.exp(-x))


class InjectionClassifier:
    def __init__(self, model_id: str = MODEL_ID) -> None:
        self.model_id = model_id
        token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
        self.tokenizer = AutoTokenizer.from_pretrained(model_id, token=token)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_id, token=token)
        self.model.to(DEVICE).eval()

        self.head = None
        if HEAD_PATH and os.path.exists(HEAD_PATH):
            npz = np.load(HEAD_PATH, allow_pickle=True)
            self.coef = npz["coef"].astype(np.float64)
            self.intercept = float(npz["intercept"])
            self.threshold = float(npz["threshold"])
            self.base = getattr(self.model, "deberta", None) or self.model.base_model
            self.pooler = getattr(self.model, "pooler", None)
            self.head = True
            self.model_id = f"{model_id}+logreg-head"  # composed model identity
        else:
            id2label = self.model.config.id2label
            self.positive_ids = [i for i, n in id2label.items()
                                 if str(n).strip().lower() in _POSITIVE] or [max(id2label.keys())]

    @torch.no_grad()
    def classify(self, text: str) -> dict:
        t0 = time.perf_counter()
        enc = self.tokenizer(text, truncation=True, max_length=MAX_TOKENS,
                             return_tensors="pt").to(DEVICE)
        if self.head:
            hs = self.base(**enc).last_hidden_state
            pooled = (self.pooler(hs) if self.pooler is not None else hs[:, 0])[0].cpu().numpy().astype(np.float64)
            score = float(_sigmoid(float(pooled @ self.coef + self.intercept)))
            malicious = score >= self.threshold
        else:
            probs = torch.softmax(self.model(**enc).logits[0], dim=-1)
            score = float(sum(probs[i] for i in self.positive_ids))
            malicious = score >= 0.5
        return {
            "verdict": "malicious" if malicious else "benign",
            "score": score,
            "model": self.model_id,
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
