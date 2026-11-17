import argparse

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="failure-forensics",
        description="Traces every step of an AI pipeline, finds where a run went wrong, and turns failures into regression test cases (first target: text-to-sql-guardrails).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args(argv)
    print("Hello from failure-forensics")
    return 0
