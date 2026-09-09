#!/usr/bin/env python3
"""Create a JavaScript/TypeScript CodeQL database and run the TaintP2X query."""

import argparse
import json
import subprocess
from pathlib import Path


def run(command):
    print("$", " ".join(map(str, command)), flush=True)
    subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="TYPESCRIPT_REPRODUCTION_CONFIG.json")
    parser.add_argument("--skip-create", action="store_true")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    root = Path(__file__).resolve().parents[1]
    cli = root / config["codeql_cli"]
    source = root / config["source_dir"]
    database = root / config["codeql_database"]
    output = root / ".workspace" / "codeql-results" / f"{config['target_name']}.sarif"
    query = root / config["codeql_query"]
    manifest = root / config["models_manifest"]
    generated_models = root / config["generated_models"]
    source_records = root / config["source_records"]
    model_command = [
        "python", str(root / "scripts" / "generate_codeql_models.py"),
        str(manifest), str(generated_models),
    ]
    if source_records.exists():
        model_command.extend(["--source-records", str(source_records)])
    run(model_command)
    if not args.skip_create:
        database.parent.mkdir(parents=True, exist_ok=True)
        run([str(cli), "database", "create", str(database), "--language", "javascript", "--source-root", str(source), "--overwrite"])
    output.parent.mkdir(parents=True, exist_ok=True)
    run([str(cli), "database", "analyze", str(database), str(query), "--search-path", str(root / config["codeql_repo"]), "--format", "sarif-latest", "--output", str(output), "--threads", "0", "--rerun"])
    print(f"SARIF: {output}")


if __name__ == "__main__":
    main()
