#!/usr/bin/env python3
"""LLM post-validation for generic TaintP2X CodeQL SARIF results.

Usage:
  python scripts/validate_codeql_results.py \
    --sarif .workspace/codeql-results/<target>.sarif \
    --source-root .workspace/project-sources/<target> \
    --output .workspace/codeql-validation/<target>.md

The validator is language-aware only at the source-context boundary: it reads
the file/line ranges reported by CodeQL and sends the resulting TypeScript or
JavaScript snippets to the same OpenAI-compatible client used by source
confirmation. It does not execute target code. A failed model call is printed
and omitted from the report rather than converted into a positive or negative result.
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "LLM-assisted_Validation"))
from ds_llm_source_determine_mul import SourceDeterminer
from ds_llm_fully_determine_mul import FullyDeterminer


PROMPT = """You are a software security expert performing a static audit. Do not run code and do not assume runtime behavior.
Review the following CodeQL taint path and determine whether it represents a valid TaintP2X vulnerability. Trace the attacker-controlled data through intermediate logic to the security-sensitive sink, and consider sanitization and whether the sink is actually security-sensitive.

Return exactly one JSON object using the original TaintP2X result contract:
{{
  "issue_number": <issue number>,
  "is_vulnerability": true or false,
  "reason": "brief evidence-based rationale",
  "triggering_conditions": "how the path can be reached and triggered"
}}

CodeQL finding:
{finding}

Taint-path source context:
{context}
"""


def line_context(path: Path, line: int, radius: int = 8) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return f"[无法读取 {path}: {exc}]"
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(f"{idx:4d}: {lines[idx - 1]}" for idx in range(start, end + 1))


def locations_for_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    locations: list[dict[str, Any]] = []
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            for item in thread.get("locations", []):
                location = item.get("location", {}).get("physicalLocation", {})
                uri = location.get("artifactLocation", {}).get("uri")
                line = location.get("region", {}).get("startLine")
                if uri and line:
                    locations.append({"uri": uri.lstrip("/"), "line": int(line), "message": item.get("location", {}).get("message", {}).get("text", "")})
    primary = result.get("locations", [{}])[0].get("physicalLocation", {})
    uri = primary.get("artifactLocation", {}).get("uri")
    line = primary.get("region", {}).get("startLine")
    if uri and line:
        locations.append({"uri": uri.lstrip("/"), "line": int(line), "message": "primary location"})
    unique = {}
    for item in locations:
        unique[(item["uri"], item["line"], item["message"])] = item
    return list(unique.values())


def parse_response(response: dict[str, Any]) -> dict[str, Any]:
    content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content:
        raise ValueError("model response has no message content")
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("model response is not a JSON object")
    parsed.setdefault("is_vulnerability", False)
    parsed.setdefault("reason", "No additional rationale returned.")
    parsed.setdefault("triggering_conditions", "")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=0, help="Validate only the first N findings; 0 means all")
    parser.add_argument("--contains", help="Only findings whose message contains this text")
    parser.add_argument("--workers", type=int, default=4, help="Concurrent model validations")
    parser.add_argument("--language", default="typescript", choices=("typescript", "javascript", "python"))
    args = parser.parse_args()

    sarif = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
    findings = sarif.get("runs", [{}])[0].get("results", [])
    if args.contains:
        findings = [item for item in findings if args.contains in item.get("message", {}).get("text", "")]
    if args.limit > 0:
        findings = findings[: args.limit]

    root = Path(args.source_root)
    source_determiner = SourceDeterminer(str(root), str(Path(args.output).parent), language=args.language)
    fully_determiner = FullyDeterminer(str(root), str(Path(args.output).parent), language=args.language)
    def validate_one(pair):
        index, finding = pair
        locations = locations_for_result(finding)
        context_parts = []
        for item in locations:
            context_parts.append(f"{item['uri']}:{item['line']} ({item['message']})\n{line_context(root / item['uri'], item['line'])}")
        context = "\n\n".join(context_parts)
        source_decision = source_determiner.confirm_codeql_finding(
            {"ruleId": finding.get("ruleId"), "message": finding.get("message", {}).get("text", "")},
            context,
            index,
        )
        decision = fully_determiner.analyze_codeql_finding(
            {"ruleId": finding.get("ruleId"), "message": finding.get("message", {}).get("text", "")},
            context,
            source_decision,
            index,
        )
        if decision is None:
            raise ValueError("final validation returned no readable JSON")
        return {"index": index, "finding": finding, "locations": locations,
                "source_decision": source_decision, "decision": parse_response({"choices": [{"message": {"content": json.dumps(decision)}}]})}

    validated = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(validate_one, pair): pair[0] for pair in enumerate(findings, 1)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                item = future.result()
            except Exception as exc:
                print(f"Finding {index} validation failed: {exc}")
                continue
            validated.append(item)
            decision = item["decision"]
            print(f"Finding {index}: is_vulnerability={decision['is_vulnerability']}")
    validated.sort(key=lambda item: item["index"])

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# TaintP2X CodeQL 后验证报告", "", f"- SARIF: `{args.sarif}`", f"- 成功后验证: {len(validated)}/{len(findings)}", ""]
    vulnerable_count = 0
    for item in validated:
        decision = item["decision"]
        vulnerable_count += bool(decision.get("is_vulnerability"))
        finding = item["finding"]
        lines.extend([
            "## Finding " + str(item["index"]),
            f"- ruleId: `{finding.get('ruleId', '')}`",
            f"- message: {finding.get('message', {}).get('text', '')}",
            f"- is_vulnerability: `{decision['is_vulnerability']}`",
            f"- reason: {decision['reason']}",
            f"- triggering_conditions: {decision['triggering_conditions']}",
            "- path locations: " + "; ".join(f"`{loc['uri']}:{loc['line']}`" for loc in item["locations"]),
            "",
        ])
    lines.extend(["## 统计", "", f"- 有效漏洞: {vulnerable_count}", f"- 非漏洞或无效路径: {len(validated) - vulnerable_count}", ""])
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(validated)} validated findings to {output}")


if __name__ == "__main__":
    main()
