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


PROMPT = """你是软件安全专家，正在进行静态审计，不要运行代码，也不要假设运行时结果。
请审查下面一条 CodeQL 污点路径，判断它是否构成可信的漏洞利用链。

传统漏洞的利用链通常是：攻击者可控输入 -> 中间逻辑 -> 安全敏感 Sink。
LLM-in-the-Loop 漏洞要求 LLM 成为链条的一部分，包括：
1. LLM 生成代码、表达式、SQL、命令或其他可执行/可解释载荷；
2. LLM 决定工具、参数、路由或特权动作；
3. 下游逻辑以安全敏感方式渲染、解析、分发或执行 LLM 输出。
如果证据不足，保守地判定为 Not-Sure，不要臆测。

只返回一个 JSON 对象，字段必须是：
{{
  "is_vulnerability": true 或 false,
  "classification": "LLM-in-the-Loop"、"traditional" 或 "Not-Sure",
  "attacker_entry_point": "攻击者入口点；证据不足写 Not-Sure",
  "exploit_chain": "从入口点经过中间逻辑到 Sink 的链路",
  "reason": "简短依据",
  "sanitized": true 或 false
}}

CodeQL 告警：
{finding}

污点路径源码上下文：
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
