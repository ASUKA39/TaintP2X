import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("OPENAI_MODEL", "test-model")

from Source_Identification.confirm_source import extract_method_implementations


class TypeScriptConfirmationTests(unittest.TestCase):
    def test_candidates_are_deduplicated_by_function_identity(self):
        candidate = {
            "file": "/target/src/agent.ts",
            "class": "Agent",
            "method": "answer",
            "method_start_line": 10,
            "method_end_line": 20,
            "method_params": "prompt",
            "attribute": "create",
            "line": 14,
            "method_code": "async answer(prompt: string) { return this.client.chat(prompt) }",
            "module": "src/agent.ts",
            "function_id": "src/agent.ts:Agent:answer:100:250",
            "sdk": {"package": "openai", "export": "OpenAI"},
        }
        duplicate_use = {**candidate, "line": 16}
        module_function = {
            **candidate,
            "class": "",
            "method": "generate",
            "function_id": "src/agent.ts::generate:300:400",
        }

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "analysis.json"
            input_path.write_text(
                json.dumps({"attribute_uses": [candidate, duplicate_use, module_function]}),
                encoding="utf-8",
            )
            methods = extract_method_implementations(str(input_path), "typescript")

        self.assertEqual(2, len(methods))
        self.assertEqual(candidate["function_id"], methods[0]["function_id"])
        self.assertEqual(candidate["sdk"], methods[0]["sdk"])
        self.assertEqual("", methods[1]["class_name"])


if __name__ == "__main__":
    unittest.main()
