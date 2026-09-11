#!/usr/bin/env python3
"""Generate one CodeQL query per original TaintP2X rule.

The rule table remains the source of truth; the generated queries only bind the
already-defined source/sink model classes and preserve each original rule id and
message.  No target-specific names are introduced here.
"""

import argparse
import json
from pathlib import Path


def ql_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def class_name(value: str, suffix: str) -> str:
    return value if value.endswith(suffix) else value + suffix


def render(rule: dict, output: Path) -> None:
    source = class_name(rule["sources"][0], "Source")
    sink_names = [class_name(name, "Sink") for name in rule.get("sinks", [])]
    sink_expr = " or ".join(
        f"sink.getNode() instanceof TaintP2XModels::{name}" for name in sink_names
    ) or "false"
    code = rule["code"]
    message = rule.get("message_format", rule.get("name", "TaintP2X finding"))
    text = f'''/**
 * Generated from Taint_Propagation/taint/taint.config.
 * @name {rule.get("name", "TaintP2X rule")}
 * @kind path-problem
 * @problem.severity warning
 * @id taintp2x/{code}
 * @tags security
 */
import javascript
import TaintP2XModels
import TaintP2XFlowQuery
import TaintP2XFlow::PathGraph

from TaintP2XFlow::PathNode source, TaintP2XFlow::PathNode sink
where
  TaintP2XFlow::flowPath(source, sink) and
  source.getNode() instanceof TaintP2XModels::{source} and
  ({sink_expr.replace('sink.getNode()', 'sink.getNode()')})
select sink.getNode(), source, sink, {ql_string(message)}
'''
    output.write_text(text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    rules = manifest.get("rules", [])
    args.output.mkdir(parents=True, exist_ok=True)
    for rule in rules:
        render(rule, args.output / f"taintp2x_{rule['code']}.ql")
    print(f"Generated {len(rules)} CodeQL rule queries in {args.output}")


if __name__ == "__main__":
    main()
