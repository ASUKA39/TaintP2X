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
and omitted from the report rather than converted into a classification.
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Source_Identification.llm_client import LLMClient


PROMPT = """You are a software security expert performing a static audit. Do not run code and do not assume runtime behavior.
Review the following CodeQL taint path and determine whether it represents a credible exploit chain.

In traditional vulnerability analysis, an exploit chain is attacker-controlled input -> intermediate logic -> security-sensitive sink.
An LLM-in-the-Loop vulnerability requires the LLM to participate in that chain in at least one of these ways:
1. The LLM generates code, expressions, SQL, commands, or another executable/interpretable payload.
2. Exploitation depends on the LLM selecting tools, constructing arguments, routing execution, or triggering a privileged action.
3. Downstream logic renders, parses, dispatches, or evaluates model output in a security-sensitive way.
When evidence is insufficient, conservatively return Not-Sure and do not speculate.

Return exactly one JSON object with these fields:
{{
  "is_vulnerability": true or false,
  "classification": "LLM-in-the-Loop", "traditional", or "Not-Sure",
  "attacker_entry_point": "attacker-controlled entry point; use Not-Sure when unsupported",
  "exploit_chain": "chain from entry point through intermediate logic to the sink",
  "reason": "brief evidence-based rationale",
  "sanitized": true or false
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
    required = {"is_vulnerability", "classification", "attacker_entry_point", "exploit_chain", "reason", "sanitized"}
    missing = required - parsed.keys()
    if missing:
        raise ValueError(f"model response missing fields: {sorted(missing)}")
    if parsed["classification"] not in {"LLM-in-the-Loop", "traditional", "Not-Sure"}:
        raise ValueError(f"invalid classification: {parsed['classification']}")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--limit", type=int, default=0, help="Validate only the first N findings; 0 means all")
    parser.add_argument("--contains", help="Only findings whose message contains this text")
    parser.add_argument("--workers", type=int, default=4, help="Concurrent model validations")
    args = parser.parse_args()

    sarif = json.loads(Path(args.sarif).read_text(encoding="utf-8"))
    findings = sarif.get("runs", [{}])[0].get("results", [])
    if args.contains:
        findings = [item for item in findings if args.contains in item.get("message", {}).get("text", "")]
    if args.limit > 0:
        findings = findings[: args.limit]

    root = Path(args.source_root)
    client = LLMClient()
    def validate_one(pair):
        index, finding = pair
        locations = locations_for_result(finding)
        context_parts = []
        for item in locations:
            context_parts.append(f"{item['uri']}:{item['line']} ({item['message']})\n{line_context(root / item['uri'], item['line'])}")
        prompt = PROMPT.format(
            finding=json.dumps({"ruleId": finding.get("ruleId"), "message": finding.get("message", {}).get("text", "")}, ensure_ascii=False),
            context="\n\n".join(context_parts),
        )
        decision = parse_response(client.complete(prompt))
        return {"index": index, "finding": finding, "locations": locations, "decision": decision}

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
            print(f"Finding {index}: {decision['classification']}")
    validated.sort(key=lambda item: item["index"])

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# TaintP2X CodeQL 后验证报告", "", f"- SARIF: `{args.sarif}`", f"- 成功后验证: {len(validated)}/{len(findings)}", ""]
    counts = {name: 0 for name in ("LLM-in-the-Loop", "traditional", "Not-Sure")}
    for item in validated:
        decision = item["decision"]
        counts[decision["classification"]] += 1
        finding = item["finding"]
        lines.extend([
            "## Finding " + str(item["index"]),
            f"- ruleId: `{finding.get('ruleId', '')}`",
            f"- message: {finding.get('message', {}).get('text', '')}",
            f"- classification: `{decision['classification']}`",
            f"- is_vulnerability: `{decision['is_vulnerability']}`",
            f"- sanitized: `{decision['sanitized']}`",
            f"- attacker_entry_point: {decision['attacker_entry_point']}",
            f"- exploit_chain: {decision['exploit_chain']}",
            f"- reason: {decision['reason']}",
            "- path locations: " + "; ".join(f"`{loc['uri']}:{loc['line']}`" for loc in item["locations"]),
            "",
        ])
    lines.extend(["## 统计", "", f"- LLM-in-the-Loop: {counts['LLM-in-the-Loop']}", f"- traditional: {counts['traditional']}", f"- Not-Sure: {counts['Not-Sure']}", ""])
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {len(validated)} validated findings to {output}")


if __name__ == "__main__":
    main()
