"""Compatibility wrapper around the original source model generator."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Source_Identification.make_pysa_source import extract_and_format_llm_paths


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("analysis_json")
    parser.add_argument("output_json")
    args = parser.parse_args()
    extract_and_format_llm_paths(args.analysis_json, args.output_json, backend="codeql")


if __name__ == "__main__":
    main()
