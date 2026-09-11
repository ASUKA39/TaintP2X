#!/usr/bin/env python3
"""Run one complete TypeScript/CodeQL reproduction in an isolated workspace.

The script only orchestrates the existing pipeline.  It does not interpret
SARIF or LLM responses and does not produce a new vulnerability verdict.
Target source and CodeQL databases are temporary; logs, SARIF, validation
artifacts, and source-identification outputs remain under the run directory.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def _run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{os.getpid()}"


def _tail(path: Path, lines: int = 30) -> str:
    if not path.exists():
        return ""
    return "".join(path.read_text(encoding="utf-8", errors="replace").splitlines(True)[-lines:])


def _run_logged(command: list[str], log_path: Path, cwd: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.run(
            command,
            cwd=cwd,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if process.returncode:
        tail = _tail(log_path)
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(command)}\n"
            + (f"last output:\n{tail}" if tail else f"log: {log_path}")
        )


def _docker_base(root: Path, image: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--mount",
        f"type=bind,src={root},dst=/taintp2x",
        "--workdir",
        "/taintp2x",
        image,
        "bash",
        "-lc",
        "",
    ]


def _copy_results(run_root: Path, target: Path, results: Path) -> None:
    results.mkdir(parents=True, exist_ok=True)
    source = target / "source"
    if source.is_dir():
        shutil.copytree(source, results / "source-identification", dirs_exist_ok=True)
    for artifact in target.glob("codeql-runs_*"):
        if artifact.is_dir():
            shutil.copytree(artifact, results / artifact.name, dirs_exist_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    config = json.loads(config_path.read_text(encoding="utf-8"))

    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY is required", file=sys.stderr)
        return 2
    image = config.get("image", "taintp2x:typescript")
    run_root = root / ".workspace" / "reproduction" / _run_id()
    target = run_root / config["target_name"]
    database = run_root / "database"
    queries = run_root / "queries"
    results = run_root / "results"
    validation = run_root / "validation"
    logs = run_root / "logs"
    run_root.mkdir(parents=True)
    shutil.copytree(root / "CodeQL_Queries", queries)

    run_config = dict(config)
    run_config.update({
        "target_name": config["target_name"],
        "source_dir": str(target.relative_to(root)),
        "codeql_database": str(database.relative_to(root)),
        "codeql_query": str((queries / "rules").relative_to(root)),
        "generated_sources": str((queries / "TaintP2XProjectSources.qll").relative_to(root)),
        "codeql_output": str((results / f"{config['target_name']}.sarif").relative_to(root)),
        "validation_log_dir": str(validation.relative_to(root)),
    })
    run_config_path = run_root / "config.json"
    run_config_path.write_text(json.dumps(run_config, indent=2), encoding="utf-8")

    try:
        print(f"Run workspace: {run_root.relative_to(root)}")
        if subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode:
            print("Building Docker image...")
            _run_logged(
                ["docker", "build", "--platform", "linux/amd64", "-f", "Dockerfile.typescript", "-t", image, "."],
                logs / "docker-build.log",
                root,
            )

        print("Cloning target...")
        _run_logged(
            ["git", "clone", "--branch", config["ref"], "--depth", "1", config["repo_url"], str(target)],
            logs / "clone.log",
            root,
        )
        actual = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
        if actual != config["expected_commit"]:
            raise RuntimeError(f"commit mismatch: expected {config['expected_commit']}, got {actual}")

        print("Installing target dependencies...")
        install = config.get("install_command", "").strip()
        if install:
            command = _docker_base(root, image)
            command[-1] = f"cd /taintp2x/{target.relative_to(root)} && {install}"
            if config.get("build_command", "").strip():
                command[-1] += f" && {config['build_command'].strip()}"
            _run_logged(command, logs / "dependency-install.log", root)

        print("Running TypeScript/CodeQL pipeline...")
        command = _docker_base(root, image)
        env_args = []
        for name, default in (
            ("OPENAI_API_KEY", os.environ["OPENAI_API_KEY"]),
            ("OPENAI_BASE_URL", "https://api.deepseek.com"),
            ("OPENAI_MODEL", "deepseek-v4-flash"),
            ("OPENAI_EXTRA_BODY", '{"thinking":{"type":"disabled"}}'),
        ):
            env_args.extend(["-e", f"{name}={os.environ.get(name, default)}"])
        command[2:2] = env_args
        command[-1] = f"python scripts/run_typescript_codeql.py --config {run_config_path.relative_to(root)}"
        _run_logged(command, logs / "analysis.log", root)
        print("Reproduction completed; results and validation artifacts were preserved.")
        print(f"Results: {results.relative_to(root)}")
        return 0
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"Reproduction failed: {exc}", file=sys.stderr)
        print(f"Logs: {logs.relative_to(root)}", file=sys.stderr)
        return 1
    finally:
        # Keep human-readable outputs, but remove the large checkout/database.
        if target.exists():
            try:
                _copy_results(run_root, target, results)
            except OSError as exc:
                print(f"Could not preserve target artifacts: {exc}", file=sys.stderr)
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        if database.exists():
            shutil.rmtree(database, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
