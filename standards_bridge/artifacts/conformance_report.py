from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from standards_bridge.profiles.specification import Decision, DomainRecord, canonical_json, stable_hash, utc_now


BUNDLE_FORMAT = "standards-bridge-bundle"
BUNDLE_FORMAT_VERSION = 2
JSON_ARTIFACTS = ("summary.json", "decisions.json", "audit-events.json")
DETAIL_ARTIFACTS = ("records.csv", "rules.csv")
RECORD_FIELDS = ("record_id", "state", "version", "source", "fingerprint", "outcome", "score")
RULE_FIELDS = ("record_id", "code", "passed", "score", "severity", "message")
SCORE_TOLERANCE = 1e-6


def ensure_output(path: str | Path) -> Path:
    output = Path(path)
    output.mkdir(parents=True, exist_ok=True)
    return output


def _atomic_write(path: Path, body: bytes) -> None:
    """Write one artifact atomically so a crash never leaves a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_json(path: Path, value: Any) -> str:
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
    _atomic_write(path, (body + "\n").encode("utf-8"))
    return stable_hash(value)


def _csv_body(fieldnames: Iterable[str], rows: Iterable[Mapping[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(fieldnames))
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def _write_csv(path: Path, fieldnames: Iterable[str], rows: list[dict[str, Any]]) -> None:
    _atomic_write(path, _csv_body(fieldnames, rows).encode("utf-8"))


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), [dict(row) for row in reader]


def _csv_content_hash(rows: Iterable[Mapping[str, Any]]) -> str:
    """Hash the semantic CSV content, tolerating line-ending and column-order differences."""
    return stable_hash([dict(row) for row in rows])


def write_records(path: Path, records: Iterable[DomainRecord], decisions: Mapping[str, Decision]) -> int:
    rows = []
    for record in records:
        decision = decisions.get(record.record_id)
        rows.append({"record_id": record.record_id, "state": record.state, "version": record.version,
                     "source": record.source, "fingerprint": record.fingerprint,
                     "outcome": decision.outcome if decision else "", "score": decision.score if decision else ""})
    _write_csv(path, RECORD_FIELDS, rows)
    return len(rows)


def write_rules(path: Path, decisions: Mapping[str, Decision]) -> int:
    rows: list[dict[str, Any]] = []
    for record_id, decision in sorted(decisions.items()):
        for result in decision.rule_results:
            rows.append({"record_id": record_id, "code": result.code, "passed": result.passed,
                         "score": result.score, "severity": result.severity, "message": result.message})
    _write_csv(path, RULE_FIELDS, rows)
    return len(rows)


def build_summary(records: list[DomainRecord], decisions: Mapping[str, Decision], snapshot: Mapping[str, Any]) -> dict[str, Any]:
    outcomes: dict[str, int] = {}
    for decision in decisions.values():
        outcomes[decision.outcome] = outcomes.get(decision.outcome, 0) + 1
    scores = [decision.score for decision in decisions.values()]
    return {"product": '中国—东盟人工智能标准适配验证台', "entity": 'adaptation_case', "generated_at": utc_now(),
            "record_count": len(records), "decision_count": len(decisions), "outcomes": outcomes,
            "average_score": sum(scores) / len(scores) if scores else 0.0,
            "minimum_score": min(scores) if scores else 0.0, "maximum_score": max(scores) if scores else 0.0,
            "repository": snapshot}


def export_bundle(output: str | Path, records: list[DomainRecord], decisions: Mapping[str, Decision],
                  snapshot: Mapping[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    root = ensure_output(output)
    summary = build_summary(records, decisions, snapshot)
    record_count = write_records(root / "records.csv", records, decisions)
    rule_count = write_rules(root / "rules.csv", decisions)
    summary_hash = write_json(root / "summary.json", summary)
    decision_hash = write_json(root / "decisions.json", [value.as_dict() for _, value in sorted(decisions.items())])
    event_hash = write_json(root / "audit-events.json", events)
    record_rows = len(_read_csv(root / "records.csv")[1])
    rule_rows = len(_read_csv(root / "rules.csv")[1])
    detail_files = {
        "records.csv": _csv_content_hash(_read_csv(root / "records.csv")[1]),
        "rules.csv": _csv_content_hash(_read_csv(root / "rules.csv")[1]),
    }
    manifest = {
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_FORMAT_VERSION,
        "files": {"summary.json": summary_hash, "decisions.json": decision_hash,
                  "audit-events.json": event_hash},
        # Detail artifacts are pinned by content as well as by row count.  They are kept
        # outside "files" so old readers that only know the JSON artifacts keep working.
        "artifacts": {"records.csv": {"content_hash": detail_files["records.csv"], "rows": record_rows},
                      "rules.csv": {"content_hash": detail_files["rules.csv"], "rows": rule_rows}},
        "detail_files": dict(detail_files),
        "record_rows": record_count,
        "rule_rows": rule_count,
        "created_at": utc_now(),
    }
    manifest["manifest_hash"] = stable_hash(manifest)
    write_json(root / "manifest.json", manifest)
    return manifest


def _manifest_body(manifest: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(manifest)
    body.pop("manifest_hash", None)
    return body


def _detail_pins(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    pins: dict[str, dict[str, Any]] = {}
    for key in ("artifacts", "detail_files", "details", "csv_files", "csv"):
        section = manifest.get(key)
        if not isinstance(section, Mapping):
            continue
        for name, value in section.items():
            if not isinstance(name, str) or not name.lower().endswith(".csv"):
                continue
            pin: dict[str, Any] = {}
            if isinstance(value, Mapping):
                pin["content_hash"] = value.get("content_hash") or value.get("hash") or value.get("sha256")
                pin["rows"] = value.get("rows")
            elif isinstance(value, str):
                pin["content_hash"] = value
            pins[name] = pin
    return pins


def _audit_chain_errors(events: Iterable[Mapping[str, Any]]) -> list[str]:
    errors: list[str] = []
    previous = "0" * 64
    for index, event in enumerate(events, start=1):
        if not isinstance(event, Mapping):
            return [f"audit-events.json entry {index} is not an object"]
        expected = stable_hash({"event_type": event.get("event_type"),
                                "aggregate_id": event.get("aggregate_id"),
                                "aggregate_version": event.get("aggregate_version"),
                                "payload": event.get("payload"),
                                "previous_hash": event.get("previous_hash"),
                                "created_at": event.get("created_at")})
        if event.get("previous_hash") != previous:
            errors.append(f"audit-events.json chain breaks at event {index}")
        if event.get("event_hash") != expected:
            errors.append(f"audit-events.json content hash mismatch at event {index}")
        previous = str(event.get("event_hash"))
    return errors


def _number(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result


def inspect_bundle(output: str | Path) -> dict[str, Any]:
    """Inspect a delivered bundle and return a structured integrity report.

    The report separates three situations that used to be conflated:

    * ``missing``/``corrupt`` – data that was promised but is absent or does not match
      its manifest/cross-checks.  These must never support certification or reuse.
    * ``legacy`` – an older manifest format that does not pin the detail artifacts.
      The artifacts may still be present; it is a format difference, not a loss.
    * ``verified`` – a fully pinned bundle whose details, summary and evidence agree.
    """
    root = Path(output)
    report: dict[str, Any] = {
        "status": "missing", "trusted": False, "usable": False, "blocked": True,
        "format_version": None, "manifest_hash": None,
        "errors": [], "warnings": [], "missing": [], "checks": [],
        "record_rows": None, "rule_rows": None, "counts": {}, "path": str(root),
    }

    def check(name: str, ok: bool, detail: str = "") -> bool:
        report["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok and detail:
            report["errors"].append(detail)
        return ok

    if not root.is_dir():
        report["errors"].append("bundle directory is missing")
        report["missing"].append("bundle directory")
        return report
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        report["errors"].append("manifest.json is missing")
        report["missing"].append("manifest.json")
        return report
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        report["errors"].append(f"manifest.json is not readable: {exc}")
        return report
    if not isinstance(manifest, Mapping):
        report["errors"].append("manifest.json is not an object")
        return report

    embedded_hash = manifest.get("manifest_hash")
    body = _manifest_body(manifest)
    if embedded_hash:
        if stable_hash(body) != embedded_hash:
            report["errors"].append("manifest hash mismatch")
        else:
            report["manifest_hash"] = str(embedded_hash)
    else:
        report["manifest_hash"] = stable_hash(body)
        report["warnings"].append("legacy manifest does not carry a manifest hash")

    version = manifest.get("format_version")
    report["format_version"] = version if isinstance(version, int) else None
    strict = isinstance(version, int) and version >= BUNDLE_FORMAT_VERSION
    if not strict:
        report["warnings"].append("legacy bundle format: detail artifacts are not pinned by the manifest")

    files = manifest.get("files")
    if not isinstance(files, Mapping):
        files = {}
        if strict:
            report["errors"].append("manifest.json does not list artifact hashes")

    json_values: dict[str, Any] = {}
    for name in JSON_ARTIFACTS:
        path = root / name
        if not path.is_file():
            report["errors"].append(f"{name} is missing")
            report["missing"].append(name)
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            report["errors"].append(f"{name} is not valid JSON")
            continue
        json_values[name] = value
        expected = files.get(name)
        if expected:
            if stable_hash(value) != expected:
                report["errors"].append(f"{name} hash mismatch")
        elif strict:
            report["errors"].append(f"{name} is not pinned by manifest.json")
        else:
            report["warnings"].append(f"legacy manifest does not pin {name}")

    pins = _detail_pins(manifest)
    detail_rows: dict[str, list[dict[str, str]]] = {}
    detail_columns: dict[str, list[str]] = {}
    for name in DETAIL_ARTIFACTS:
        path = root / name
        if not path.is_file():
            report["errors"].append(f"{name} is missing")
            report["missing"].append(name)
            continue
        try:
            columns, rows = _read_csv(path)
        except (OSError, UnicodeDecodeError, csv.Error):
            report["errors"].append(f"{name} is not readable")
            continue
        detail_rows[name] = rows
        detail_columns[name] = columns
        pin = pins.get(name) or {}
        if pin.get("content_hash"):
            if _csv_content_hash(rows) != pin["content_hash"]:
                report["errors"].append(f"{name} hash mismatch")
        elif strict:
            report["errors"].append(f"{name} is not pinned by manifest.json")
        else:
            report["warnings"].append(f"legacy manifest does not pin {name}")
        pinned_rows = pin.get("rows")
        if pinned_rows is not None and _number(pinned_rows) is not None and int(pinned_rows) != len(rows):
            report["errors"].append(f"{name} row count mismatch")

    records_rows = detail_rows.get("records.csv")
    rules_rows = detail_rows.get("rules.csv")
    report["record_rows"] = len(records_rows) if records_rows is not None else None
    report["rule_rows"] = len(rules_rows) if rules_rows is not None else None

    # Row totals declared by the manifest must agree with the delivered details.
    declared_records = manifest.get("record_rows")
    declared_rules = manifest.get("rule_rows")
    for label, declared, actual in (("record_rows", declared_records, report["record_rows"]),
                                    ("rule_rows", declared_rules, report["rule_rows"])):
        if declared is None:
            if strict:
                report["errors"].append(f"manifest.json does not declare {label}")
        elif actual is not None and _number(declared) is not None and int(declared) != actual:
            report["errors"].append(f"manifest.json {label} does not match the delivered details")

    summary = json_values.get("summary.json")
    decisions = json_values.get("decisions.json")
    events = json_values.get("audit-events.json")
    if isinstance(events, list):
        report["errors"].extend(_audit_chain_errors(events))
    elif "audit-events.json" in json_values:
        report["errors"].append("audit-events.json is not a list")

    if records_rows is not None:
        columns = detail_columns.get("records.csv", [])
        missing_columns = [name for name in RECORD_FIELDS if name not in columns]
        if missing_columns:
            message = f"records.csv is missing columns: {', '.join(missing_columns)}"
            if strict:
                report["errors"].append(message)
            else:
                report["warnings"].append(message)
        else:
            ids = [row.get("record_id", "") for row in records_rows]
            duplicates = sorted(name for name, count in Counter(ids).items() if count > 1)
            if duplicates:
                report["errors"].append(f"records.csv repeats case details: {', '.join(duplicates)}")

    if rules_rows is not None:
        columns = detail_columns.get("rules.csv", [])
        missing_columns = [name for name in RULE_FIELDS if name not in columns]
        if missing_columns:
            message = f"rules.csv is missing columns: {', '.join(missing_columns)}"
            if strict:
                report["errors"].append(message)
            else:
                report["warnings"].append(message)

    if isinstance(decisions, list) and all(isinstance(item, Mapping) for item in decisions):
        decision_by_id: dict[str, Mapping[str, Any]] = {}
        for item in decisions:
            record_id = str(item.get("record_id", ""))
            if record_id in decision_by_id:
                report["errors"].append(f"decisions.json repeats case {record_id}")
            decision_by_id[record_id] = item
        report["counts"]["decisions"] = len(decisions)
        if records_rows is not None and all(name in detail_columns.get("records.csv", []) for name in RECORD_FIELDS):
            records_by_id = {row.get("record_id", ""): row for row in records_rows}
            if set(decision_by_id) - set(records_by_id):
                missing = sorted(set(decision_by_id) - set(records_by_id))
                report["errors"].append(f"records.csv is missing cases listed in decisions.json: {', '.join(missing)}")
            for record_id, decision in decision_by_id.items():
                row = records_by_id.get(record_id)
                if row is None:
                    continue
                if row.get("outcome") != decision.get("outcome"):
                    report["errors"].append(f"records.csv outcome does not match decisions.json for {record_id}")
                    break
                left, right = _number(row.get("score")), _number(decision.get("score"))
                if left is not None and right is not None and abs(left - right) > SCORE_TOLERANCE:
                    report["errors"].append(f"records.csv score does not match decisions.json for {record_id}")
                    break
        if rules_rows is not None and "record_id" in detail_columns.get("rules.csv", []):
            per_record = Counter(row.get("record_id", "") for row in rules_rows)
            for record_id, decision in decision_by_id.items():
                rules = decision.get("rules")
                expected = len(rules) if isinstance(rules, list) else 0
                if per_record.get(record_id, 0) != expected:
                    report["errors"].append(f"rules.csv does not match decisions.json for {record_id}")
                    break
        report["counts"]["outcomes"] = dict(Counter(str(item.get("outcome", "")) for item in decisions))
        scores = [value for value in (_number(item.get("score")) for item in decisions) if value is not None]
        if scores:
            report["counts"].update({"average_score": sum(scores) / len(scores),
                                     "minimum_score": min(scores), "maximum_score": max(scores)})
    elif "decisions.json" in json_values:
        report["errors"].append("decisions.json is not a list")

    if isinstance(summary, Mapping):
        report["counts"]["summary"] = {
            "record_count": summary.get("record_count"), "decision_count": summary.get("decision_count"),
            "outcomes": summary.get("outcomes"),
        }
        if report["record_rows"] is not None and summary.get("record_count") != report["record_rows"]:
            report["errors"].append("summary.json record_count does not match records.csv")
        if isinstance(decisions, list) and summary.get("decision_count") != len(decisions):
            report["errors"].append("summary.json decision_count does not match decisions.json")
        expected_outcomes = report["counts"].get("outcomes")
        if expected_outcomes is not None and summary.get("outcomes") != expected_outcomes:
            report["errors"].append("summary.json outcomes do not match decisions.json")
        for key in ("average_score", "minimum_score", "maximum_score"):
            if key in report["counts"] and summary.get(key) is not None:
                declared, actual = _number(summary.get(key)), report["counts"][key]
                if declared is not None and abs(declared - actual) > SCORE_TOLERANCE:
                    report["errors"].append(f"summary.json {key} does not match decisions.json")
    elif "summary.json" in json_values:
        report["errors"].append("summary.json is not an object")

    if report["errors"]:
        report["status"] = "corrupt"
    elif not strict:
        report["status"] = "legacy"
    else:
        report["status"] = "verified"
    # Only a fully pinned bundle is "trusted"; a legacy bundle is still usable when
    # its details are present and cross-check, but must be upgraded to be re-issued.
    report["trusted"] = report["status"] == "verified"
    report["usable"] = report["status"] in ("verified", "legacy")
    report["blocked"] = not report["usable"]
    report["requires_upgrade"] = report["status"] == "legacy"
    # Warnings are format differences, not loss; only errors deny a conclusion.
    report["errors"] = list(dict.fromkeys(report["errors"]))
    report["warnings"] = list(dict.fromkeys(report["warnings"]))
    report["blocking_reasons"] = list(report["errors"])
    return report


def verify_bundle(output: str | Path) -> list[str]:
    """Backwards-compatible integrity check returning the blocking errors."""
    return list(inspect_bundle(output)["errors"])


# Descriptive aliases used by callers that prefer an explicit audit vocabulary.
bundle_report = inspect_bundle
audit_bundle = inspect_bundle
verify_bundle_details = inspect_bundle
