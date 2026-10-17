"""
Fast classifier stage (optional).

A pretrained prompt-injection classifier that runs on CPU in roughly 0.1 s per
prompt. It is used only to BLOCK confident detections early, saving an LLM
call. It never marks anything SAFE: measurements showed it misses too many
attacks (see evaluation/) to be trusted to skip the LLM judge.

Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0, ungated).
Requires the optional extra:  pip install "mi-guard[classifier]"

The block threshold is on the injection probability. Use it on user prompts;
it false-alarms on benign tool output (see evaluation/).
"""

import os
from typing import Optional, Tuple

MODEL_NAME = os.environ.get(
    "MI_GUARD_CLASSIFIER_MODEL", "protectai/deberta-v3-base-prompt-injection-v2"
)
BLOCK_THRESHOLD = float(os.environ.get("MI_GUARD_BLOCK_THRESHOLD", "0.90"))

_pipe = None
_unavailable = False


def _load():
    global _pipe, _unavailable
    if _pipe is not None or _unavailable:
        return _pipe
    try:
        from transformers import pipeline
        _pipe = pipeline("text-classification", model=MODEL_NAME,
                         truncation=True, max_length=512)
    except Exception:
        _unavailable = True
    return _pipe


def injection_probability(text: str) -> Optional[float]:
    """Probability the text is a prompt injection, or None if unavailable."""
    pipe = _load()
    if pipe is None:
        return None
    out = pipe(text)[0]
    score = float(out["score"])
    return score if out["label"].upper().startswith("INJECTION") else 1.0 - score


def classifier_filter(text: str) -> Optional[Tuple[str, str]]:
    """Return ("MALICIOUS", reason) when the classifier is confident, else None
    (meaning: send it on to the LLM judge)."""
    p = injection_probability(text)
    if p is not None and p >= BLOCK_THRESHOLD:
        return ("MALICIOUS", f"Fast classifier: injection probability {p:.3f}.")
    return None
