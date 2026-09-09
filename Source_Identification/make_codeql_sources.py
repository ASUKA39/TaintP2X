"""Convert confirmed TypeScript LLM calls to an auditable CodeQL model list."""

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis_json")
    parser.add_argument("output_json")
    args = parser.parse_args()
    records = json.loads(Path(args.analysis_json).read_text(encoding="utf-8"))
    sources = [
        {
            "module": item.get("module"),
            "method": item.get("method"),
            "line": item.get("line"),
            "attribute": item.get("attribute"),
            "full_method_path": item.get("full_method_path"),
            "reason": item.get("reason", ""),
        }
        for item in records
        if item.get("is_llm_call") is True
    ]
    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(json.dumps({"sources": sources}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(sources)} CodeQL source records to {args.output_json}")


if __name__ == "__main__":
    main()
