"""ONNX-runtime injection classifier — torch-free path for the benchmark.

The production escalation service (escalation-tier/classifier.py) uses
transformers+torch on a GPU. This environment has no torch wheel (x86_64/Rosetta
Python), so for the LOCAL benchmark we run the model's pre-exported ONNX graph via
onnxruntime instead. Same semantics, same {score, verdict} interface.

Defaults to protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0, ungated,
ships an onnx/ export). Prompt Guard 2 is gated and has no public onnx export, so
it is not runnable here — see README; run it on a torch machine with an HF token.
"""
from __future__ import annotations
import os
import time
import json
import numpy as np
import onnxruntime as ort
from huggingface_hub import snapshot_download
from transformers import AutoTokenizer

MODEL_ID = os.environ.get("MODEL_ID", "protectai/deberta-v3-base-prompt-injection-v2")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "512"))
_POSITIVE = {"malicious", "injection", "jailbreak", "label_1", "1", "unsafe", "inj"}


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max())
    return e / e.sum()


class OnnxInjectionClassifier:
    def __init__(self, model_id: str = MODEL_ID) -> None:
        self.model_id = model_id
        # Pull only the onnx/ subfolder (model + tokenizer + config).
        local = snapshot_download(model_id, allow_patterns=["onnx/*"])
        onnx_dir = os.path.join(local, "onnx")
        self.tokenizer = AutoTokenizer.from_pretrained(onnx_dir)
        self.session = ort.InferenceSession(
            os.path.join(onnx_dir, "model.onnx"), providers=["CPUExecutionProvider"]
        )
        self._input_names = {i.name for i in self.session.get_inputs()}
        cfg = json.load(open(os.path.join(onnx_dir, "config.json")))
        id2label = cfg.get("id2label", {"0": "SAFE", "1": "INJECTION"})
        self.positive_ids = [
            int(i) for i, name in id2label.items() if str(name).strip().lower() in _POSITIVE
        ] or [max(int(i) for i in id2label)]

    def classify(self, text: str) -> dict:
        t0 = time.perf_counter()
        enc = self.tokenizer(text, truncation=True, max_length=MAX_TOKENS, return_tensors="np")
        feed = {}
        for name in self._input_names:
            if name in enc:
                feed[name] = enc[name].astype(np.int64)
            elif name == "token_type_ids":
                feed[name] = np.zeros_like(enc["input_ids"], dtype=np.int64)
        logits = self.session.run(None, feed)[0][0]
        probs = _softmax(np.asarray(logits, dtype=np.float64))
        score = float(sum(probs[i] for i in self.positive_ids))
        return {
            "verdict": "malicious" if score >= 0.5 else "benign",
            "score": score,
            "model": self.model_id,
            "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
