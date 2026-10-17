#!/usr/bin/env python3
"""Fail when the Action reads a report field the documented contract does not define.

`scripts/test-action-contract` used to grep `action.yml` for the exact report
fields it consumed, so when the schema moved to v3 the greps pinned the removed
v2 names and CI failed. This reads the documented field sets from
`report_schema.py` and checks every `report.*`/`finding.*`/`location.*` access
inside the Action's `script:` blocks against them, so a schema change only
breaks the contract test when the Action really reads a field that is gone.
"""

import importlib.util
import re
import sys

# JavaScript object names used inside the Action's scripts, mapped to the sets
# of documented field names in `report_schema.py`.
CONSUMERS = {
    "report": "TOP_LEVEL_REQUIRED",
    "finding": "VIOLATION_FIELDS",
    "location": "LOCATION_FIELDS",
}
# Reads the Action must keep: annotation titles come from the report's rules map.
REQUIRED_READS = (("report", "rules"), ("finding", "rule_id"))

BLOCK = re.compile(r"^(\s*)script:\s*\|")
ACCESS = re.compile(r"\b(report|finding|location)\.([A-Za-z_][A-Za-z0-9_]*)")


def load_schema(path):
    spec = importlib.util.spec_from_file_location("report_schema", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def script_blocks(text):
    """The lines of every YAML block scalar introduced by `script: |`."""
    lines = text.splitlines()
    blocks = []
    index = 0
    while index < len(lines):
        match = BLOCK.match(lines[index])
        if match is None:
            index += 1
            continue
        indent = len(match.group(1))
        index += 1
        start = index
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            index += 1
        blocks.append("\n".join(lines[start:index]))
    return blocks


def reads(text):
    """Every (object, field) access found in the Action's script blocks."""
    found = set()
    for block in script_blocks(text):
        found.update(ACCESS.findall(block))
    return found


def main(argv):
    if len(argv) != 3:
        print("usage: action-report-contract.py <action.yml> <report_schema.py>", file=sys.stderr)
        return 2
    schema = load_schema(argv[2])
    documented = {root: set(getattr(schema, attribute)) for root, attribute in CONSUMERS.items()}
    try:
        with open(argv[1], encoding="utf-8") as handle:
            found = reads(handle.read())
    except OSError as error:
        print(f"unreadable manifest: {error}", file=sys.stderr)
        return 1
    problems = sorted(
        f"{root}.{field}" for root, field in found if field not in documented[root]
    )
    for field in problems:
        print(f"Action reads undocumented report field '{field}'", file=sys.stderr)
    for root, field in REQUIRED_READS:
        if (root, field) not in found:
            print(f"Action no longer reads the documented field '{root}.{field}'", file=sys.stderr)
            problems.append(f"{root}.{field}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
