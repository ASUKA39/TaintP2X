import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from Source_Identification.make_pysa_source import extract_and_format_llm_paths


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class CodeQLSourceGenerationTests(unittest.TestCase):
    def test_confirmed_source_keeps_exact_function_identity(self):
        confirmed = [
            {
                "is_llm_call": True,
                "full_method_path": "src.first.Agent.answer",
                "file_path": "/target/src/first.ts",
                "module": "src/first.ts",
                "class_name": "Agent",
                "method_name": "answer",
                "start_line": 10,
                "end_line": 20,
                "function_id": "src/first.ts:Agent:answer:100:250",
                "attribute_name": "create",
                "reason": "confirmed",
            },
            {
                "is_llm_call": True,
                "full_method_path": "src.second.Agent.answer",
                "file_path": "/target/src/second.ts",
                "module": "src/second.ts",
                "class_name": "Agent",
                "method_name": "answer",
                "start_line": 30,
                "end_line": 40,
                "function_id": "src/second.ts:Agent:answer:300:450",
                "attribute_name": "create",
                "reason": "confirmed",
            },
        ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis_path = root / "analysis.json"
            records_path = root / "sources.json"
            qll_path = root / "Models.qll"
            analysis_path.write_text(json.dumps(confirmed), encoding="utf-8")

            extract_and_format_llm_paths(
                str(analysis_path), str(records_path), backend="codeql"
            )
            records = json.loads(records_path.read_text(encoding="utf-8"))
            subprocess.run(
                [
                    "python",
                    str(REPOSITORY_ROOT / "scripts" / "generate_codeql_models.py"),
                    str(REPOSITORY_ROOT / "CodeQL_Models" / "taintp2x_models.json"),
                    str(qll_path),
                    "--source-records",
                    str(records_path),
                ],
                check=True,
            )
            generated = qll_path.read_text(encoding="utf-8")

        self.assertEqual("src/first.ts", records["sources"][0]["module"])
        self.assertEqual("Agent", records["sources"][0]["class"])
        self.assertEqual(10, records["sources"][0]["start_line"])
        self.assertEqual(20, records["sources"][0]["end_line"])
        self.assertIn('function.getFile().getRelativePath() = "src/first.ts"', generated)
        self.assertIn('function.getFile().getRelativePath() = "src/second.ts"', generated)
        self.assertIn("call.getACallee() = function", generated)
        self.assertNotIn('call.getCalleeName() in ["create"]', generated)


if __name__ == "__main__":
    unittest.main()
