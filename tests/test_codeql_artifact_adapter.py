import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("OPENAI_API_KEY", "test-key")

from run_download_and_check import _write_codeql_issue_artifact
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "LLM-assisted_Validation"))
from ds_llm_fully_determine_mul import FullyDeterminer


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


if __name__ == "__main__":
    unittest.main()
