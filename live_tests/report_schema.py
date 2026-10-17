"""Validate a safe-migrate lint report against the published report schema.

`run.sh` used to read only `violations[].rule_id`, so a bumped schema or a
dropped `verdict` left every fixture green. These checks are written against
`docs/CONTRACT.md` rather than the producer, so agreement is evidence. The one
deliberate coupling is `EXPECTED_SCHEMA_VERSION`, a tripwire for a schema change
that belongs in a changelog.
"""

import json
import re
import sys

# The schema version `docs/CONTRACT.md` publishes. Bump this only together with
# the contract and the changelog entry that explains the change.
EXPECTED_SCHEMA_VERSION = 3

CONFIDENCE_VALUES = {"Exact", "Tainted"}
VERDICT_VALUES = {"HALT", "CAUTIOUS", "SAFE WITH RISK", "SAFE"}
TIER_VALUES = {"Tier1", "Tier2", "Tier3"}
CERTAINTY_VALUES = {"Exact", "Assumed", "Tainted"}
EVIDENCE_SCOPE_VALUES = {"statement", "chain"}
BASELINE_STATUS_VALUES = {"available", "stale", "unavailable"}
AUTO_SYNC_VALUES = {"not_requested", "refreshed", "failed", "bypassed"}
# `EvidenceCode` is serialized snake_case and is `#[non_exhaustive]`, so the set
# is checked for shape rather than enumerated.
SNAKE_CASE = re.compile(r"^[a-z][a-z0-9_]*$")

VIOLATION_REQUIRED = ("rule_id", "object_kind", "object_name", "tier", "reason", "recipe")
VIOLATION_OPTIONAL = ("sql", "statement_index", "certainty", "location")
# Documented field names a consumer may rely on, including nested location keys.
VIOLATION_FIELDS = VIOLATION_REQUIRED + VIOLATION_OPTIONAL
LOCATION_FIELDS = ("file", "line", "column")
NOT_EVALUATED_REQUIRED = ("rule_id", "tier", "cause", "recipe")
EVIDENCE_REQUIRED = ("code", "scope", "summary")
TOP_LEVEL_REQUIRED = (
    "schema_version",
    "confidence",
    "verdict",
    "summary",
    "evidence",
    "not_evaluated",
    "rules",
    "violations",
    "baseline",
)


class SchemaError(Exception):
    pass


def _require(condition, message):
    if not condition:
        raise SchemaError(message)


def _is_string(value, _what=None):
    return isinstance(value, str) and value != ""


def _is_count(value, _what=None):
    # `bool` is an `int` subclass in Python; a count is never a boolean.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_position(value, _what=None):
    # Lines and statement indexes are one-based, so zero is never valid.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _check_enum(value, allowed, what):
    _require(value in allowed, f"{what} {value!r} is not one of {sorted(allowed)}")


def _check_optional(container, field, check, what):
    if field in container and container[field] is not None:
        check(container[field], f"{what}.{field}")


def check_violation(violation):
    _require(isinstance(violation, dict), "violation is not an object")
    # `rule_id` is the finding's identity and must be usable; `object_name` may
    # legitimately be empty for a finding that is not about one object.
    _require(_is_string(violation.get("rule_id")), "violation.rule_id must be a non-empty string")
    for field in ("object_kind", "reason", "recipe"):
        _require(_is_string(violation.get(field)), f"violation.{field} must be a non-empty string")
    _require(isinstance(violation.get("object_name"), str), "violation.object_name must be a string")
    _check_enum(violation["tier"], TIER_VALUES, "violation.tier")
    _check_optional(violation, "sql", _is_string, "violation")
    _check_optional(violation, "statement_index", _is_position, "violation")
    _check_optional(violation, "certainty", lambda v, w: _check_enum(v, CERTAINTY_VALUES, w), "violation")
    location = violation.get("location")
    if location is not None:
        _require(isinstance(location, dict), "violation.location must be an object")
        _require(_is_count(location.get("file")) is False and _is_string(location.get("file")),
                 "violation.location.file must be a non-empty string")
        _require(_is_position(location.get("line")), "violation.location.line must be a one-based position")
        _check_optional(location, "column", _is_count, "violation.location")


def check_not_evaluated(entry):
    _require(isinstance(entry, dict), "not_evaluated entry is not an object")
    for field in NOT_EVALUATED_REQUIRED:
        _require(_is_string(entry.get(field)), f"not_evaluated.{field} must be a non-empty string")
    _check_enum(entry["tier"], TIER_VALUES, "not_evaluated.tier")
    _require(SNAKE_CASE.match(entry["cause"]), f"not_evaluated.cause {entry['cause']!r} is not snake_case")
    _check_optional(entry, "sql", _is_string, "not_evaluated")
    schemas = entry.get("missing_schemas")
    if schemas is not None:
        _require(isinstance(schemas, list) and all(_is_string(name) for name in schemas),
                 "not_evaluated.missing_schemas must be a list of names")


def check_evidence(entry):
    _require(isinstance(entry, dict), "evidence entry is not an object")
    for field in EVIDENCE_REQUIRED:
        _require(_is_string(entry.get(field)), f"evidence.{field} must be a non-empty string")
    _require(SNAKE_CASE.match(entry["code"]), f"evidence.code {entry['code']!r} is not snake_case")
    _check_enum(entry["scope"], EVIDENCE_SCOPE_VALUES, "evidence.scope")
    location = entry.get("location")
    if location is not None:
        _require(isinstance(location, dict), "evidence.location must be an object")
        _require(_is_string(location.get("file")), "evidence.location.file must be a non-empty string")
        _require(_is_position(location.get("statement_index")), "evidence.location.statement_index must be a one-based position")


def check_baseline(baseline):
    _require(isinstance(baseline, dict), "baseline must be an object")
    _check_enum(baseline.get("status"), BASELINE_STATUS_VALUES, "baseline.status")
    _check_enum(baseline.get("auto_sync"), AUTO_SYNC_VALUES, "baseline.auto_sync")
    # Creation provenance is null when there is no baseline to describe, which
    # is also what makes a readable baseline stale.
    created_at = baseline.get("created_at_unix_secs")
    _require(created_at is None or _is_count(created_at),
             "baseline.created_at_unix_secs must be null or a count")
    _check_optional(baseline, "source_database", _is_string, "baseline")
    schemas = baseline.get("schemas")
    if schemas is not None:
        _require(isinstance(schemas, list) and all(_is_string(name) for name in schemas),
                 "baseline.schemas must be a list of names")
    settings = baseline.get("observed_settings")
    if settings is not None:
        _require(isinstance(settings, dict), "baseline.observed_settings must be an object")
        for field in ("lock_timeout_ms", "statement_timeout_ms"):
            value = settings.get(field)
            _require(value is None or _is_count(value),
                     f"baseline.observed_settings.{field} must be null or a count")


def check_report(report):
    """Raise `SchemaError` unless the report satisfies the documented schema."""
    _require(isinstance(report, dict), "report is not an object")
    for field in TOP_LEVEL_REQUIRED:
        _require(field in report, f"report is missing the documented field '{field}'")

    version = report["schema_version"]
    _require(_is_count(version), "schema_version must be a count")
    _require(
        version == EXPECTED_SCHEMA_VERSION,
        f"schema_version is {version}, expected {EXPECTED_SCHEMA_VERSION}; the schema "
        f"changed, so this checker and CONTRACT.md must change with it",
    )

    _check_enum(report["confidence"], CONFIDENCE_VALUES, "confidence")
    _check_enum(report["verdict"], VERDICT_VALUES, "verdict")

    violations = report["violations"]
    _require(isinstance(violations, list), "violations must be a list")
    for violation in violations:
        check_violation(violation)

    # The summary is derived from the findings, so a disagreement means one of
    # the two is wrong and the report cannot be trusted either way.
    summary = report["summary"]
    _require(isinstance(summary, dict), "summary must be an object")
    for field in ("total", "tier1", "tier2", "tier3"):
        _require(_is_count(summary.get(field)), f"summary.{field} must be a count")
    _require(
        summary["total"] == len(violations),
        f"summary.total is {summary['total']} but there are {len(violations)} violations",
    )
    for tier in (1, 2, 3):
        counted = sum(1 for violation in violations if violation["tier"] == f"Tier{tier}")
        _require(
            summary[f"tier{tier}"] == counted,
            f"summary.tier{tier} is {summary[f'tier{tier}']} but {counted} findings are Tier{tier}",
        )

    not_evaluated = report["not_evaluated"]
    _require(isinstance(not_evaluated, list), "not_evaluated must be a list")
    for entry in not_evaluated:
        check_not_evaluated(entry)

    # Recompute the documented verdict ladder; a report may not claim a safer
    # verdict than its findings and skipped checks allow.
    has_tier1 = any(violation["tier"] == "Tier1" for violation in violations)
    has_tier2 = any(violation["tier"] == "Tier2" for violation in violations)
    has_irreversible = any(
        violation["tier"] == "Tier3" and violation["rule_id"] == "irreversible-migration"
        for violation in violations
    )
    skipped_tier1 = any(entry["tier"] == "Tier1" for entry in not_evaluated)
    if has_tier1:
        expected_verdict = "HALT"
    elif has_tier2 or skipped_tier1:
        expected_verdict = "CAUTIOUS"
    elif has_irreversible:
        expected_verdict = "SAFE WITH RISK"
    else:
        expected_verdict = "SAFE"
    _require(
        report["verdict"] == expected_verdict,
        f"the findings and skipped checks imply {expected_verdict!r}, not {report['verdict']!r}",
    )

    evidence = report["evidence"]
    _require(isinstance(evidence, list), "evidence must be a list")
    for entry in evidence:
        check_evidence(entry)

    rules = report["rules"]
    _require(isinstance(rules, dict), "rules must be an object")
    for rule_id, title in rules.items():
        _require(_is_string(rule_id) and _is_string(title),
                 "rules must map a non-empty rule_id to a non-empty title")
    for source, entries in (("violation", violations), ("not_evaluated", not_evaluated)):
        for entry in entries:
            _require(
                entry["rule_id"] in rules,
                f"{source} names rule '{entry['rule_id']}' but rules has no title for it",
            )

    check_baseline(report["baseline"])


def main(argv):
    if len(argv) != 2:
        print("usage: report_schema.py <report.json>", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        print(f"unreadable report: {error}", file=sys.stderr)
        return 1
    try:
        check_report(report)
    except SchemaError as error:
        print(f"report schema: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
