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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["project_root"] = str(root)
    source = root / config["source_dir"]
    project_name = source.name
    has_issue = run_project_pipeline(str(source), language="typescript", backend="codeql", config=config)
    if has_issue:
        import sys
        sys.path.insert(0, str(root / "LLM-assisted_Validation"))
        from ds_llm_source_determine_mul import SourceDeterminer
        from ds_llm_fully_determine_mul import FullyDeterminer
        log_dir = root / "llm_validation_logs"
        taint_output = source / ("codeql-runs_" + project_name) / "taint-output.json"
        source_determiner = SourceDeterminer(str(source.parent), str(log_dir), language="typescript")
        fully_determiner = FullyDeterminer(str(source.parent), str(log_dir), language="typescript")
        source_determiner.process_project(project_name, str(taint_output))
        fully_determiner.process_project(project_name, str(taint_output), str(log_dir))
    print(f"CodeQL findings: {has_issue}")


if __name__ == "__main__":
    main()
