#!/usr/bin/env python3
"""Compatibility entry point for the original check driver.

The CodeQL backend is implemented in ``run_download_and_check.run_pysa_check``
so the TypeScript port does not introduce a second analysis driver.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run_download_and_check import run_project_pipeline
from run_download_and_check import run_pysa_check


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="TYPESCRIPT_REPRODUCTION_CONFIG.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["project_root"] = str(root)
    source = root / config["source_dir"]
    project_name = source.name
    analysis_file = source / "source" / f"analysis_source_{project_name}.json"
    confirmation_file = source / "source" / f"llm_analysis_{project_name}.json"
    source_records = source / "source" / "codeql_sources.json"
    if analysis_file.exists() and confirmation_file.exists() and source_records.exists():
        print("Source Identification artifacts already exist; skipping confirmation stage.")
        has_issue = run_pysa_check(str(source), backend="codeql", config=config)
    else:
        has_issue = run_project_pipeline(str(source), language="typescript", backend="codeql", config=config)
    print(f"CodeQL findings: {has_issue}")


if __name__ == "__main__":
    main()
