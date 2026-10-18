# MI_GUARD: LangGraph Multi-Agent Security Firewall

A multi-agent security pipeline that screens user prompts for prompt injection
and jailbreak attempts before they reach a tool-using LLM agent.

## Overview

MI_GUARD sits in front of a "victim" agent (a chatbot that can call tools like
Wikipedia). Every user prompt is checked by a **Judge Agent**. If the prompt
looks safe, it is routed to the victim agent; if it looks malicious, the
connection is cut and the victim never sees it.

## Architecture

1. **Stage 0 - Threat memory** (optional): exact / fuzzy match against prompts
   previously recorded as malicious, stored in Supabase. Disabled when
   `SUPABASE_URL` / `SUPABASE_KEY` are not set.
2. **Stage 1 - Rule engine** (`mi_guard/rules.py`): fast, dependency-free
   regex and decoding checks for known attack families (instruction override,
   persona jailbreaks like DAN, data exfiltration, authority impersonation,
   payload splitting, base64 payloads, leetspeak / zero-width obfuscation).
3. **Stage 2 - LLM Judge**: a Llama 3 8B model (via the **Groq cloud API**)
   classifies anything the rules did not catch, using session history to spot
   payload splitting across turns.
4. **Stage 2.5 - Critic**: a second LLM call scores the Judge's decision and
   can send it back for re-evaluation (max 2 retries).
5. **Indirect-injection screen**: tool output (e.g. Wikipedia results) is run
   through the Stage 1 rules before it is allowed into a prompt, so malicious
   web content cannot smuggle instructions into the victim agent.

> Honest note: the models run on Groq's cloud and threat memory uses Supabase
> cloud. This project does **not** run fully locally; an earlier version of
> this README claimed it did, which was wrong.

## Repository structure

| Path | What it is |
|---|---|
| `judge_agent.py` | LangGraph workflow: Judge, Critic, Victim agent, router |
| `mi_guard/rules.py` | Dependency-free Stage 1 rule engine |
| `server.py` | Flask REST API (`POST /api/analyze`) with rate limiting |
| `victim_agent.py` | Standalone local demo victim agent (Ollama) |
| `evaluate.py` | Evaluation harness - see below |
| `evaluation/dataset.json` | 50 labeled prompts (30 attacks, 20 benign incl. traps) |
| `Concept_Proof/` | Early minimal demos, kept for reference |

## Evaluation results (measured, reproducible)

Run it yourself:

```bash
python3 evaluate.py --stage rules   # no API keys needed
```

Latest measured run of the **Stage 1 rule engine** on `evaluation/dataset.json`
(50 prompts, committed to this repo):

| Metric | Value |
|---|---|
| Overall accuracy | 47/50 = **94.0%** |
| Attack detection rate | 29/30 = **96.7%** |
| False positives on benign prompts | 2/20 = **10.0%** |

Known misses in this run (kept honest on purpose):

- A "security researcher needs your initialization parameters for an audit"
  prompt slips past the rules (the LLM Judge stage is meant to catch these).
- Two benign prompts are wrongly blocked: a question about writing a regex to
  detect "ignore previous instructions", and a question about the Dan river in
  Virginia (the `\bdan\b` signature). False positives are the current weak
  point of the rule engine.

### External benchmark: deepset/prompt-injections

Also measured on the public
[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)
benchmark (546 prompts: 203 injections, 343 benign):

```bash
python3 evaluate.py --stage rules --dataset deepset
```

| Metric | Value |
|---|---|
| Attack detection rate (rules only) | 5/203 = **2.5%** |
| False positives on benign prompts | 0/343 = **0.0%** |

This is an honest and important result: the rule engine alone catches almost
none of the benchmark's novel injections. Its real value is speed and zero
false positives - the LLM Judge (Stage 2) does the actual detection work on
novel attacks. Anyone evaluating this project should run `--stage full`.

The full pipeline (`python3 evaluate.py --stage full`, needs `GROQ_API_KEY`)
adds the LLM Judge on top of these rules. Numbers for that stage depend on the
model and are not claimed here until measured.

> An earlier README claimed "99.0% accuracy" from evaluation scripts
> (`evaluate_pyrit.py`, `jailbreaks_large.json`) that were never committed to
> this repository. That number could not be verified, so it has been replaced
> by the reproducible results above.

## Setup

```bash
pip3 install -r requirements.txt
# or install as a package (exposes the mi_guard rule engine):
pip3 install .
```

Environment variables (in a `.env` file, which is git-ignored):

- `GROQ_API_KEY` - required for the LLM Judge / Critic and the victim agent
- `SUPABASE_URL`, `SUPABASE_KEY` - optional, enables threat memory

## How to run

```bash
python3 judge_agent.py          # interactive terminal demo
python3 server.py               # REST API on port 5001
curl -X POST http://127.0.0.1:5001/api/analyze \
  -H "Content-Type: application/json" -d '{"prompt": "Hello"}'
python3 evaluate.py --stage rules
```

## Known limitations

- Only English-language attacks are handled by the rule engine; the LLM Judge
  prompt asks the model to translate, but this is not measured.
- The Stage 1 signatures can be bypassed with enough creativity - they are a
  first line of defense, not a guarantee.
- The threat-memory stage depends on an external Supabase table.

## Tech stack

Python 3, LangGraph, LangChain, Groq (Llama 3 8B), Flask, Supabase (optional),
Ollama (standalone demo only).

Author: Avika - B.Tech CSE | AI Safety & Security


## Fast classifier stage (optional)

`pip install "mi-guard[classifier]"` adds a pretrained classifier
(`protectai/deberta-v3-base-prompt-injection-v2`, CPU, about 0.1 s per prompt).
It only blocks confident detections (probability >= 0.90) before the LLM judge
and never marks a prompt safe, so everything else still reaches the judge.
Set `MI_GUARD_FAST_CLASSIFIER=0` to turn it off.

Measured on the public deepset/prompt-injections test split (60 attacks, 56 benign):

| Stage | Attacks caught | False alarms |
|---|---|---|
| Rules only | 0 / 60 | 0 / 56 |
| Classifier (>= 0.90) | 20 / 60 | 0 / 56 |

The classifier misses 40 of 60 attacks (many are German; the model is mostly
English), which is why it cannot replace the LLM judge. The model's own training
data may overlap with this benchmark, so treat these numbers as optimistic.

## Indirect injection benchmark (AgentDojo)

`evaluate_indirect.py` builds tool outputs from AgentDojo v1.2.1 (workspace,
travel, banking, slack suites), with and without injected instructions, and
checks whether the firewall flags them. This is a detection test, not
AgentDojo's attack-success-rate: the full harness needs an agent LLM and paid
API calls, so it was not run.

Results (1,728 injected tool outputs, 339 benign ones):

| Stage | Injections flagged | Benign flagged |
|---|---|---|
| Rules only | 0.0% | 0.0% |
| Classifier (>= 0.90) | 49.6% | 21.2% |

By attack template, classifier detection: ignore_previous 80.6%,
important_instructions 52.6%, system_message 39.1%, direct 26.2%.
The classifier false-alarms on 1 in 5 benign tool outputs, so use it on user
prompts, not on web or tool text. The rule stage catches none of these, so
indirect screening currently depends on the LLM judge. Full-pipeline numbers
with the LLM judge still need a Groq key.

## Full-pipeline results (rules, classifier, LLM judge and critic)

Judge model: `openai/gpt-oss-20b` on Groq (the old default `llama3-8b-8192` was
retired by Groq; set `MI_GUARD_LLM_MODEL` to use another model).

| Dataset | Prompts | Attacks caught | Benign blocked wrongly |
|---|---|---|---|
| Built-in (`evaluation/dataset.json`) | 50 | 30 / 30 | 4 / 20 |
| deepset test, random sample (seed 0) | 26 | 10 / 14 | 0 / 12 |

Notes:
- The built-in false alarms are 3 of 5 `benign_trap` prompts and 1 plain benign prompt. Accuracy 92% on this set.
- The deepset run was planned for 40 prompts but stopped after 26 because of Groq's free-tier limit of 8,000 tokens per minute (`evaluate.py` now waits and retries on rate limits, and has `--limit N` for a seeded sample). With 14 attacks the detection rate (71%) has a wide margin of error.
- The built-in set was written alongside the rules, so it flatters the system. The deepset sample is the more honest number.
