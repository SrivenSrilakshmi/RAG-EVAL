# RAG Security Risk Evaluation Project

This project evaluates security risks in a Retrieval-Augmented Generation (RAG) system and measures defense effectiveness.

## Features

- RAG stack using LangChain + FAISS (deterministic local hash embeddings)
- Enterprise-style knowledge base from text files under `data/`
- Attack simulations:
  - Normal query answering
  - Prompt injection attacks
  - Retrieval poisoning attacks
  - Knowledge leakage attempts
- Metrics:
  - Attack Success Rate (ASR)
  - Leakage Rate
  - Response correctness
- Defenses:
  - Prompt filtering
  - Prompt separation via system/user/context templates
  - Output filtering/redaction
- CSV logs and summary tables generated per run

## Project Structure

- `data/` knowledge base files
- `attacks/` attack scenario definitions
- `defenses/` defense logic
- `evaluation/` experiment runner and metrics
- `results/` generated CSV outputs

## Setup

1. Create and activate a virtual environment.

PowerShell:

```powershell
cd C:\Users\srive\rag-security-eval
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies.

```powershell
pip install -r requirements.txt
```

Required packages are intentionally minimal for reproducibility on Windows/Python 3.14.

## Run Experiments

```powershell
python run_experiments.py
```

This command runs two conditions:

- `baseline`: no defenses
- `defended`: prompt filtering + prompt separation + output redaction

## Reproduce Results

1. Use the same dataset in `data/`.
2. Run `python run_experiments.py`.
3. Inspect CSV outputs in `results/`:
   - `experiment_logs_<timestamp>.csv`
   - `summary_asr_<timestamp>.csv`
   - `summary_leakage_<timestamp>.csv`
   - `summary_correctness_<timestamp>.csv`
   - `summary_utility_<timestamp>.csv`

Each run writes a full per-scenario experiment log plus summary tables for:
- ASR before/after defense
- Leakage Rate before/after defense
- Utility impact (correctness delta)

## Interpreting Utility Impact

Utility impact is computed as:

`Correctness_after_defense - Correctness_before_defense`

Positive means defenses improved utility, negative means they reduced utility.
