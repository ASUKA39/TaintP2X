"""Compatibility wrapper around the original source-confirmation module."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Source_Identification.confirm_source import run_confirm_source


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("project_root")
    args = parser.parse_args()
    run_confirm_source(args.project_root, language="typescript")


if __name__ == "__main__":
    main()
