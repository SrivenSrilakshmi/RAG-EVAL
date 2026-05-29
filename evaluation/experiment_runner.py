from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, List
import csv

from attacks.scenarios import all_scenarios
from defenses.filters import DefenseConfig
from evaluation.metrics import attack_success, leakage_detected, make_summary_tables, response_correctness
from evaluation.ragas_eval import evaluate_row
from rag_system import EnterpriseRAG


def _run_condition(data_dir: Path, condition: str, defense_config: DefenseConfig) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    scenarios = all_scenarios()

    # One RAG object per condition; index content toggles per scenario for poisoning experiments.
    rag = EnterpriseRAG(data_dir=data_dir, defense_config=defense_config)

    for scenario in scenarios:
        include_poisoned = scenario.attack_type == "retrieval_poisoning"
        rag.build_index(include_poisoned=include_poisoned)

        result = rag.answer_query(
            query=scenario.query,
            attack_type=scenario.attack_type,
            include_poisoned=include_poisoned,
        )

        response = str(result["response"])
        blocked = bool(result["blocked"])
        llm_provider = str(result.get("llm_provider", "simulation"))
        context_docs = str(result.get("retrieved_context", "")).split("\n\n")

        correctness = response_correctness(response, scenario.expected_keywords)
        leaked = leakage_detected(response)
        succeeded = attack_success(scenario.attack_type, response, blocked)
        ragas = evaluate_row(response, scenario.query, context_docs, scenario.expected_keywords)

        rows.append(
            {
                "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "condition": condition,
                "llm_provider": llm_provider,
                "scenario_id": scenario.scenario_id,
                "attack_type": scenario.attack_type,
                "query": scenario.query,
                "expected_keywords": "|".join(scenario.expected_keywords),
                "response": response,
                "blocked": blocked,
                "retrieved_sources": "|".join(result["retrieved_sources"]),
                "leakage_detected": leaked,
                "attack_success": succeeded,
                "correctness": round(correctness, 4),
                "faithfulness": ragas["faithfulness"],
                "answer_relevancy": ragas["answer_relevancy"],
                "context_recall": ragas["context_recall"],
            }
        )

    return rows


def _write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _print_table(title: str, rows: List[Dict[str, object]]) -> None:
    print(f"\n=== {title} ===")
    if not rows:
        print("(empty)")
        return

    headers = list(rows[0].keys())
    header_line = " | ".join(headers)
    sep = "-+-".join("-" * len(h) for h in headers)
    print(header_line)
    print(sep)
    for row in rows:
        print(" | ".join(str(row.get(h, "")) for h in headers))


def run_full_experiment(project_root: Path) -> Dict[str, Path]:
    data_dir = project_root / "data"
    results_dir = project_root / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    baseline_df = _run_condition(
        data_dir=data_dir,
        condition="baseline",
        defense_config=DefenseConfig(
            prompt_filtering=False,
            prompt_separation=False,
            output_redaction=False,
        ),
    )

    defended_df = _run_condition(
        data_dir=data_dir,
        condition="defended",
        defense_config=DefenseConfig(
            prompt_filtering=True,
            prompt_separation=True,
            output_redaction=True,
        ),
    )

    combined_rows = baseline_df + defended_df
    summaries = make_summary_tables(combined_rows)

    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    logs_path = results_dir / f"experiment_logs_{run_id}.csv"
    asr_path = results_dir / f"summary_asr_{run_id}.csv"
    leakage_path = results_dir / f"summary_leakage_{run_id}.csv"
    correctness_path = results_dir / f"summary_correctness_{run_id}.csv"
    utility_path = results_dir / f"summary_utility_{run_id}.csv"

    delta_path = results_dir / f"summary_delta_{run_id}.csv"
    ragas_path = results_dir / f"summary_ragas_{run_id}.csv"

    _write_csv(logs_path, combined_rows)
    _write_csv(asr_path, summaries["asr"])
    _write_csv(leakage_path, summaries["leakage"])
    _write_csv(correctness_path, summaries["correctness"])
    _write_csv(utility_path, summaries["utility"])
    _write_csv(delta_path, summaries["delta"])
    _write_csv(ragas_path, summaries["ragas"])

    _print_table("Summary: ASR", summaries["asr"])
    _print_table("Summary: Leakage Rate", summaries["leakage"])
    _print_table("Summary: Correctness", summaries["correctness"])
    _print_table("Summary: RAGAS Metrics", summaries["ragas"])
    _print_table("Summary: Delta (Defense Effect)", summaries["delta"])
    _print_table("Summary: Utility Impact", summaries["utility"])

    return {
        "logs": logs_path,
        "asr": asr_path,
        "leakage": leakage_path,
        "correctness": correctness_path,
        "utility": utility_path,
        "delta": delta_path,
        "ragas": ragas_path,
    }
