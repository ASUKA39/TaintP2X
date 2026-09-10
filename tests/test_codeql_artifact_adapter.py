import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("OPENAI_MODEL", "test-model")

from run_download_and_check import _write_codeql_issue_artifact
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "LLM-assisted_Validation"))
from ds_llm_fully_determine_mul import FullyDeterminer
from ds_llm_source_determine_mul import SourceDeterminer


class CodeQLArtifactAdapterTests(unittest.TestCase):
    def test_preserves_ordered_path_and_original_trace_names(self):
        sarif = {
            "runs": [{
                "results": [{
                    "ruleId": "taintp2x/5001",
                    "message": {"text": "model output reaches sink"},
                    "codeFlows": [{"threadFlows": [{"locations": [
                        {"location": {"physicalLocation": {
                            "artifactLocation": {"uri": "src/agent.ts"},
                            "region": {"startLine": 10, "startColumn": 3},
                        }}},
                        {"location": {"physicalLocation": {
                            "artifactLocation": {"uri": "src/runner.ts"},
                            "region": {"startLine": 42, "startColumn": 9},
                        }}},
                    ]}]}],
                }]
            }]
        }
        with tempfile.TemporaryDirectory() as directory:
            output = _write_codeql_issue_artifact(directory, sarif)
            records = json.loads(Path(output).read_text(encoding="utf-8"))
        data = records[0]["data"]
        self.assertEqual(["src/agent.ts", "src/runner.ts"],
                         [entry["file_path"] for entry in data["codeql_path"]])
        self.assertEqual(["source", "forward", "backward"],
                         [trace["name"] for trace in data["traces"]])
        self.assertEqual(10, data["traces"][0]["roots"][0]["location"]["line"])
        self.assertEqual(42, data["sink"]["line"])


class TypeScriptContextTests(unittest.TestCase):
    def test_extracts_brace_delimited_function(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "agent.ts"
            source.write_text(
                "export class Agent {\n"
                "  async answer(prompt: string) {\n"
                "    const value = await client.chat(prompt);\n"
                "    return value;\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            determiner = object.__new__(FullyDeterminer)
            determiner.language = "typescript"
            content = determiner.extract_method_by_line(str(source), 3)
        self.assertIn("async answer", content)
        self.assertIn("return value", content)
        self.assertNotIn("export class Agent", content)

    def test_source_stage_creates_nested_log_directory_and_extracts_ts(self):
        class Fake:
            def chat_completion(self, **kwargs):
                return {"choices": [{"message": {"content": json.dumps({
                    "issue_number": 1,
                    "is_vulnerability": True,
                    "reason": "calls a conversational model",
                    "triggering_conditions": "prompt reaches the client",
                })}}]}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "demo"
            (project / "src").mkdir(parents=True)
            (project / "src" / "agent.ts").write_text(
                "export function answer(prompt: string) {\n"
                "  return prompt;\n"
                "}\n", encoding="utf-8"
            )
            taint = root / "taint.json"
            taint.write_text(json.dumps([{"kind": "issue", "data": {
                "callable": "src/agent.ts",
                "traces": [{"name": "source", "roots": [{"location": {
                    "filename": "src/agent.ts", "line": 2
                }}]}]
            }}]), encoding="utf-8")
            determiner = SourceDeterminer(str(root), str(root / "new-logs"), language="typescript")
            determiner.llm_client = Fake()
            determiner.process_project("demo", str(taint))
            context = root / "new-logs" / "demo" / "1" / "context_output.txt"
            self.assertTrue(context.exists())
            self.assertIn("answer", context.read_text(encoding="utf-8"))

    def test_fully_stage_runs_after_source_gate_and_writes_original_artifacts(self):
        class Fake:
            def __init__(self):
                self.calls = 0

            def chat_completion(self, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    value = {
                        "issue_number": 1,
                        "is_taint_valid": True,
                        "has_sanitizer": False,
                        "sanitizer_functions": [],
                        "function_analysis": [],
                        "analysis_reason": "path reaches sink",
                    }
                else:
                    value = {
                        "issue_number": 1,
                        "is_vulnerability": True,
                        "reason": "sink is reachable",
                        "triggering_conditions": "attacker controls the prompt",
                    }
                return {"choices": [{"message": {"content": json.dumps(value)}}]}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "demo"
            (project / "src").mkdir(parents=True)
            (project / "src" / "agent.ts").write_text(
                "export function answer(prompt: string) {\n"
                "  return prompt;\n"
                "}\n", encoding="utf-8"
            )
            logs = root / "logs" / "demo" / "1"
            logs.mkdir(parents=True)
            (logs / "response_output.json").write_text(
                json.dumps({"is_vulnerability": True}), encoding="utf-8"
            )
            taint = root / "taint.json"
            taint.write_text(json.dumps([{"kind": "issue", "data": {
                "callable": "src/agent.ts",
                "codeql_path": [{
                    "function": "answer", "file_path": "src/agent.ts",
                    "line": 2, "start_line": 1, "params": "prompt",
                }],
            }}]), encoding="utf-8")
            determiner = FullyDeterminer(str(root), str(root / "logs"), language="typescript")
            determiner.llm_client = Fake()
            determiner.process_project("demo", str(taint), str(root / "logs"))
            self.assertTrue((logs / "trace_chain.log").exists())
            result = logs / "analysis_results.json"
            self.assertTrue(result.exists())
            self.assertTrue(json.loads(result.read_text(encoding="utf-8"))[
                "analysis"]["chain_analysis"]["is_vulnerability"])


if __name__ == "__main__":
    unittest.main()
