# tools/junit_annotations.py - Turn pytest failures into GitHub annotations.
#
# A failing job's log is only readable when signed in to GitHub, but its
# annotations are part of the public check-run API. Printing each failed test
# as an "::error" line makes the reason visible on the PR's checks page and
# to anyone (or any tool) reading the check run - not just "exit code 1".
#
# Usage (in a workflow step that runs only on failure):
#   pytest ... --junitxml=results.xml
#   python tools/junit_annotations.py results.xml

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# GitHub truncates long annotations; keep the end of the traceback (the
# assertion and the values involved are at the bottom)
MAX_MESSAGE_CHARS = 3000


def _escape(text: str) -> str:
    """GitHub workflow-command escaping for the message part."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotations(xml_text: str) -> list:
    """One '::error title=<test>::<message>' line per failed or errored test."""
    lines = []
    for case in ET.fromstring(xml_text).iter("testcase"):
        for outcome in ("failure", "error"):
            node = case.find(outcome)
            if node is None:
                continue
            name = f"{case.get('classname', '')}.{case.get('name', '')}".strip(".")
            detail = "\n".join(p for p in (node.get("message"), node.text) if p).strip()
            title = _escape(name).replace(",", "%2C").replace(":", "%3A")
            lines.append(
                f"::error title={outcome.upper()} {title}::{_escape(detail[-MAX_MESSAGE_CHARS:])}"
            )
    return lines


def main(argv: list | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python tools/junit_annotations.py results.xml")
        return 2
    path = Path(args[0])
    if not path.is_file():
        print(f"::warning::{path} not found - pytest did not write a report")
        return 0
    for line in annotations(path.read_text(encoding="utf-8")):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
