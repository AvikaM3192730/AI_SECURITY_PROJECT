"""
MI_GUARD evaluation harness.
============================

Measures how well the firewall classifies a labeled dataset of benign and
malicious prompts, and reports honest numbers - including false positives,
which matter as much as caught attacks.

Two stages can be evaluated:

  --stage rules   (default) Stage 1 rule engine only (mi_guard.rules).
                  Pure standard library: runs anywhere, no API keys needed.

  --stage full    The complete LangGraph pipeline from judge_agent.py,
                  including the LLM Judge and Critic. Requires GROQ_API_KEY
                  (and optionally SUPABASE_URL/SUPABASE_KEY for threat
                  memory). Slow and costs API calls - use for final numbers.

Results are written to evaluation/results_<stage>.json and printed.

Usage:
  python3 evaluate.py --stage rules
  GROQ_API_KEY=... python3 evaluate.py --stage full
"""

import argparse
import json
import os
import sys
import time

DATASET_PATH = os.path.join(os.path.dirname(__file__), "evaluation", "dataset.json")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "evaluation")

MAX_PROMPT_LENGTH = 1500  # mirror judge_agent's context limit


def load_deepset(split="train"):
    """Download + cache the public deepset/prompt-injections benchmark."""
    cache = os.path.join(RESULTS_DIR, "external", f"deepset_{split}.parquet")
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    if not os.path.exists(cache):
        import urllib.request
        url = ("https://huggingface.co/api/datasets/deepset/"
               f"prompt-injections/parquet/default/{split}/0.parquet")
        print(f"Downloading {url} ...")
        urllib.request.urlretrieve(url, cache)
    import pandas as pd
    df = pd.read_parquet(cache)
    # label 1 = prompt injection, 0 = benign
    return [
        {"id": f"ds{i:04d}", "prompt": row.text,
         "label": "malicious" if row.label == 1 else "benign",
         "family": "deepset_injection" if row.label == 1 else "deepset_benign"}
        for i, row in enumerate(df.itertuples())
    ]


def classify_rules(prompt: str):
    """Stage 1 rule engine only. Returns (verdict, reason)."""
    from mi_guard.rules import stage1_filter
    if len(prompt) > MAX_PROMPT_LENGTH:
        return ("MALICIOUS", "Exceeds maximum prompt length.")
    result = stage1_filter(prompt)
    if result:
        return result
    # NOTE: with --stage rules, anything not caught by the signatures is
    # assumed SAFE. The full pipeline's LLM Judge catches more, so rule-stage
    # false-negative numbers are an upper bound.
    return ("SAFE", "No rule signature matched.")


def classify_classifier(prompt: str):
    """Fast classifier stage on its own (mi_guard.classifier)."""
    from mi_guard.classifier import injection_probability, BLOCK_THRESHOLD
    p = injection_probability(prompt)
    return ("MALICIOUS" if p >= BLOCK_THRESHOLD else "SAFE", f"p={p:.4f}")


def classify_full(prompt: str):
    """Full LangGraph pipeline. Returns (verdict, reason)."""
    from judge_agent import app as judge_app
    state = judge_app.invoke({"user_input": prompt, "session_history": []})
    return (state.get("verdict", "UNKNOWN"), state.get("reason", ""))


def main():
    parser = argparse.ArgumentParser(description="MI_GUARD evaluation harness")
    parser.add_argument("--stage", choices=["rules", "classifier", "full"], default="rules")
    parser.add_argument(
        "--dataset", choices=["builtin", "deepset", "deepset_test"], default="builtin",
        help="builtin = evaluation/dataset.json; deepset = the public "
             "deepset/prompt-injections benchmark (546 prompts, downloaded "
             "from HuggingFace and cached under evaluation/external/).")
    args = parser.parse_args()

    if args.dataset == "deepset":
        dataset = load_deepset("train")
    elif args.dataset == "deepset_test":
        dataset = load_deepset("test")
    else:
        with open(DATASET_PATH, encoding="utf-8") as f:
            dataset = json.load(f)

    classify = {"rules": classify_rules, "classifier": classify_classifier,
                "full": classify_full}[args.stage]

    if args.stage == "full" and not os.environ.get("GROQ_API_KEY"):
        print("Error: --stage full requires GROQ_API_KEY in the environment.")
        sys.exit(1)

    records = []
    tp = tn = fp = fn = 0
    per_family = {}
    t0 = time.time()

    for item in dataset:
        verdict, reason = classify(item["prompt"])
        predicted = "malicious" if verdict == "MALICIOUS" else "benign"
        actual = item["label"]
        correct = predicted == actual

        if actual == "malicious" and predicted == "malicious":
            tp += 1
        elif actual == "malicious":
            fn += 1
        elif predicted == "malicious":
            fp += 1
        else:
            tn += 1

        fam = item["family"]
        per_family.setdefault(fam, {"total": 0, "correct": 0})
        per_family[fam]["total"] += 1
        per_family[fam]["correct"] += int(correct)

        records.append({
            "id": item["id"], "family": fam, "label": actual,
            "predicted": predicted, "correct": correct, "reason": reason,
        })
        flag = "OK " if correct else "MISS"
        print(f"[{flag}] {item['id']} ({fam}): predicted={predicted} actual={actual}")

    total = len(dataset)
    elapsed = time.time() - t0
    summary = {
        "stage": args.stage,
        "dataset": args.dataset,
        "total": total,
        "correct": tp + tn,
        "accuracy": round((tp + tn) / total, 4),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "false_positive_rate_on_benign": round(fp / (fp + tn), 4) if (fp + tn) else None,
        "detection_rate_on_attacks": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "per_family": per_family,
        "elapsed_seconds": round(elapsed, 2),
    }

    out_path = os.path.join(RESULTS_DIR, f"results_{args.stage}_{args.dataset}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "records": records}, f, indent=2)

    print("\n==== SUMMARY ====")
    print(json.dumps(summary, indent=2))
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()
