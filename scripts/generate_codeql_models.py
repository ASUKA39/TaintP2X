#!/usr/bin/env python3
"""Generate the CodeQL model module from the language-port model manifest."""

import argparse
import json
from pathlib import Path


def ql_string(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def values(items):
    return "[" + ", ".join(ql_string(value) for value in items) + "]"


def call_predicate(names: list[str], indent: str = "      ") -> str:
    if not names:
        return "false"
    return f"call.getCalleeName() in {values(names)}"


def property_predicate(names: list[str]) -> str:
    if not names:
        return "false"
    return f"read.getPropertyName() in {values(names)}"


def source_class(name: str, spec: dict) -> str:
    class_name = name if name.endswith("Source") else f"{name}Source"
    calls = spec.get("call_names", [])
    props = spec.get("property_names", [])
    return f'''  class {class_name} extends TaintP2XSource {{
    {class_name}() {{
      exists(DataFlow::CallNode call | ({call_predicate(calls)} and this = call))
      or
      exists(DataFlow::PropRead read | ({property_predicate(props)} and this = read))
    }}

    override string getKind() {{ result = "{name}" }}
  }}
'''


def sink_class(name: str, spec: dict) -> str:
    class_name = name if name.endswith("Sink") else f"{name}Sink"
    calls = spec.get("call_names", [])
    props = spec.get("property_names", [])
    globals_ = spec.get("global_names", [])
    clauses = []
    if calls:
        clauses.append(f"exists(DataFlow::CallNode call | ({call_predicate(calls)} and this = call.getAnArgument()))")
    if props:
        clauses.append(f"exists(DataFlow::PropRead read | ({property_predicate(props)} and this = read))")
    if globals_:
        clauses.append(
            "exists(string name, DataFlow::InvokeNode invocation | "
            f"name in {values(globals_)} and invocation = DataFlow::globalVarRef(name).getAnInvocation() and "
            "this = invocation.getAnArgument())"
        )
    condition = "\n      or\n      ".join(clauses) if clauses else "false"
    return f'''  class {class_name} extends TaintP2XSink {{
    {class_name}() {{
      {condition}
    }}

    override string getCategory() {{ result = "{name}" }}
  }}
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("output")
    parser.add_argument("--source-records", help="Confirmed Source JSON; method attributes are merged into the model")
    args = parser.parse_args()
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    if args.source_records:
        records = json.loads(Path(args.source_records).read_text(encoding="utf-8"))
        confirmed = records.get("sources", records if isinstance(records, list) else [])
        source = manifest.setdefault("sources", {}).setdefault("LLMControlled", {})
        names = set(source.setdefault("call_names", []))
        for record in confirmed:
            if record.get("attribute"):
                names.add(record["attribute"])
        source["call_names"] = sorted(names)
    output = Path(args.output)
    text = [
        "/** Generated from CodeQL_Models/taintp2x_models.json; edit the manifest, not this file. */",
        "import javascript",
        "",
        "module TaintP2XModels {",
        "  abstract class TaintP2XSource extends DataFlow::Node {",
        "    abstract string getKind();",
        "  }",
        "",
        "  abstract class TaintP2XSink extends DataFlow::Node {",
        "    abstract string getCategory();",
        "  }",
        "",
    ]
    for name, spec in manifest.get("sources", {}).items():
        text.append(source_class(name, spec))
    for name, spec in manifest.get("sinks", {}).items():
        text.append(sink_class(name, spec))
    sanitizer_names = manifest.get("sanitizers", {}).get("call_names", [])
    sanitizer_condition = call_predicate(sanitizer_names)
    transform_names = manifest.get("transforms", {}).get("FileOperation", {}).get("call_names", [])
    transform_condition = call_predicate(transform_names)
    text.extend([
        "  class TaintP2XSanitizer extends DataFlow::Node {",
        "    TaintP2XSanitizer() {",
        f"      exists(DataFlow::CallNode call | ({sanitizer_condition} and this = call))",
        "    }",
        "  }",
        "",
        "  predicate isFileOperationCall(DataFlow::CallNode call) {",
        f"    {transform_condition}",
        "  }",
        "}",
        "",
    ])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(text), encoding="utf-8")
    print(f"Generated {output}")


if __name__ == "__main__":
    main()
