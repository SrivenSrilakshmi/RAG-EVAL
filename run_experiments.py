from pathlib import Path

from evaluation.experiment_runner import run_full_experiment


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent
    output_paths = run_full_experiment(project_root)

    print("\n=== Output Files ===")
    for name, path in output_paths.items():
        print(f"{name}: {path}")
