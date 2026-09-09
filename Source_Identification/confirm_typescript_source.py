"""Confirm TypeScript LLM-call candidates with the configured OpenAI-compatible model."""

import argparse
import json
import os
from pathlib import Path

from .llm_client import LLMClient


PROMPT = """判断下面的 TypeScript/JavaScript 函数是否调用大模型或返回大模型输出。
只返回 JSON：{{"is_llm_call": true 或 false, "reason": "简短原因"}}。
已知调用方法候选可能来自 OpenAI、Anthropic、LangChain、Google、Ollama、Groq、Mistral 或其他模型 SDK。

函数：
{method_code}
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis_json")
    parser.add_argument("output_json")
    parser.add_argument("--limit", type=int, default=0, help="Only confirm the first N candidates; 0 means all")
    args = parser.parse_args()
    client = LLMClient()
    records = json.loads(Path(args.analysis_json).read_text(encoding="utf-8"))
    results = []
    candidates = records.get("attribute_uses", [])
    if args.limit > 0:
        candidates = candidates[: args.limit]
    for item in candidates:
        try:
            response = client.analyze_code(PROMPT, item["method_code"])
            content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
            decision = json.loads(content)
            item = dict(item)
            item.update(decision)
            item["full_method_path"] = f"{item.get('module', '').rsplit('.', 1)[0]}.{item.get('method')}"
            results.append(item)
        except Exception as exc:  # one bad model response must not discard other candidates
            print(f"TypeScript source confirmation failed at {item.get('file')}:{item.get('line')}: {exc}")
            results.append({**item, "is_llm_call": False, "reason": f"confirmation error: {exc}"})
    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(results)} TypeScript source confirmations to {args.output_json}")


if __name__ == "__main__":
    main()
