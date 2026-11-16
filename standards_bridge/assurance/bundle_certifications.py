"""验证包登记与认证签发使用项目的正式包校验入口。

完整性状态会被持久化到案例账本，因此认证、复用与平台复核都不依赖某次
命令行调用是否恰好多打印了一条错误：

* ``trusted``  —— 明细、统计与依据互相核对通过，可支撑待认证与待复用结论。
* ``legacy``   —— 旧版清单格式（未固定明细文件哈希），但明细确实存在且能
                  与统计/依据核对；这是格式差异，不是丢失。
* ``blocked``  —— 明细缺失、哈希不符或交叉核对失败，不得继续支撑任何结论。

已签发的认证事实永不删除或改写；包后来损坏时只追加风险信息。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from standards_bridge.profiles.specification import ContractError, canonical_json, utc_now
from standards_bridge.artifacts.conformance_report import inspect_bundle
from standards_bridge.assurance.certification_register import ensure_certification_evidence

TRUSTED = "trusted"
LEGACY = "legacy"
BLOCKED = "blocked"
UNKNOWN = "unknown"


def _install_schema(connection) -> None:
    connection.execute("""CREATE TABLE IF NOT EXISTS certification_bundles(
        bundle_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        mapping_id TEXT NOT NULL,
        path TEXT NOT NULL,
        manifest_hash TEXT NOT NULL
    )""")
    existing = {row[1] for row in connection.execute("PRAGMA table_info(certification_bundles)")}
    additions = {
        "integrity": "TEXT NOT NULL DEFAULT 'unknown'",
        "checked_at": "TEXT",
        "format_version": "INTEGER",
        "record_rows": "INTEGER",
        "rule_rows": "INTEGER",
        "errors_json": "TEXT NOT NULL DEFAULT '[]'",
        "warnings_json": "TEXT NOT NULL DEFAULT '[]'",
        "report_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for name, declaration in additions.items():
        if name not in existing:
            connection.execute(f"ALTER TABLE certification_bundles ADD COLUMN {name} {declaration}")
    connection.execute("""CREATE TABLE IF NOT EXISTS bundle_integrity_history(
        history_id INTEGER PRIMARY KEY AUTOINCREMENT,
        bundle_id TEXT NOT NULL,
        status TEXT NOT NULL,
        manifest_hash TEXT,
        errors_json TEXT NOT NULL,
        warnings_json TEXT NOT NULL,
        checked_at TEXT NOT NULL
    )""")
    ensure_certification_evidence(connection)


def ensure_certification_evidence(connection) -> None:
    """Keep evidence (and its bundle identity) on the immutable certification row."""
    try:
        existing = {row[1] for row in connection.execute("PRAGMA table_info(certifications)")}
    except Exception:
        return
    if "evidence_json" not in existing:
        connection.execute("ALTER TABLE certifications ADD COLUMN evidence_json TEXT NOT NULL DEFAULT '{}'")
    if "bundle_id" not in existing:
        connection.execute("ALTER TABLE certifications ADD COLUMN bundle_id TEXT")


def _status_for(report: dict[str, Any]) -> str:
    if report.get("status") == "verified":
        return TRUSTED
    if report.get("status") == "legacy":
        return LEGACY
    return BLOCKED


class BundleCertifications:
    def __init__(self, repository):
        self.repository = repository
        with repository.connect() as connection:
            _install_schema(connection)

    # ------------------------------------------------------------------ helpers
    def _row(self, bundle_id: str):
        with self.repository.connect() as connection:
            return connection.execute("SELECT * FROM certification_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()

    def _record_report(self, bundle_id: str, report: dict[str, Any], connection=None) -> dict[str, Any]:
        status = _status_for(report)
        errors = list(report.get("errors") or [])
        warnings = list(report.get("warnings") or [])
        checked_at = utc_now()
        publishable = dict(report)
        publishable.pop("path", None)
        owns = connection is None
        connection = connection or self.repository.connect()
        try:
            if owns:
                connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT integrity,errors_json,warnings_json FROM certification_bundles WHERE bundle_id=?",
                (bundle_id,)).fetchone()
            connection.execute(
                "UPDATE certification_bundles SET integrity=?,checked_at=?,format_version=?,record_rows=?,"
                "rule_rows=?,errors_json=?,warnings_json=?,report_json=? WHERE bundle_id=?",
                (status, checked_at, report.get("format_version"), report.get("record_rows"),
                 report.get("rule_rows"), canonical_json(errors), canonical_json(warnings),
                 canonical_json(publishable), bundle_id))
            changed = previous is None or previous["integrity"] != status or \
                json.loads(previous["errors_json"] or "[]") != errors or \
                json.loads(previous["warnings_json"] or "[]") != warnings
            if changed:
                connection.execute(
                    "INSERT INTO bundle_integrity_history(bundle_id,status,manifest_hash,errors_json,"
                    "warnings_json,checked_at) VALUES(?,?,?,?,?,?)",
                    (bundle_id, status, report.get("manifest_hash"), canonical_json(errors),
                     canonical_json(warnings), checked_at))
                self.repository.append_event(connection, "bundle.verified", bundle_id,
                                             self.repository.event_count(bundle_id, connection) + 1,
                                             {"status": status, "manifest_hash": report.get("manifest_hash"),
                                              "errors": errors, "warnings": warnings})
            if owns:
                connection.commit()
        except Exception:
            if owns:
                connection.rollback()
            raise
        finally:
            if owns:
                connection.close()
        return {"bundle_id": bundle_id, "status": status, "integrity": status,
                "trusted": status in (TRUSTED, LEGACY), "blocked": status == BLOCKED,
                "requires_upgrade": status == LEGACY, "completeness": "intact" if status != BLOCKED else "damaged",
                "errors": errors, "warnings": warnings, "missing": list(report.get("missing") or []),
                "manifest_hash": report.get("manifest_hash"), "format_version": report.get("format_version"),
                "record_rows": report.get("record_rows"), "rule_rows": report.get("rule_rows"),
                "checked_at": checked_at}

    # ------------------------------------------------------------------- public
    def register(self, bundle_id: str, case_id: str, mapping_id: str, path):
        path = Path(path).resolve()
        report = inspect_bundle(path)
        if not report["usable"]:
            details = "; ".join(report["errors"]) or "验证包不完整"
            raise ContractError(f"验证包完整性核验失败: {details}")
        manifest_hash = report.get("manifest_hash") or ""
        with self.repository.transaction() as connection:
            if not connection.execute("SELECT 1 FROM records WHERE record_id=?", (case_id,)).fetchone():
                raise ContractError("案例不存在")
            values = (case_id, mapping_id, str(path))
            old = connection.execute("SELECT * FROM certification_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
            if old:
                if (old["case_id"], old["mapping_id"], old["path"]) != values:
                    raise ContractError("验证包登记不能覆盖")
                if old["manifest_hash"] == manifest_hash:
                    result = dict(old)
                    self._record_report(bundle_id, report, connection)
                    result.update({"integrity": _status_for(report), "trusted": True,
                                   "manifest_hash": manifest_hash})
                    return result
                # A package that was previously unusable may be re-completed/re-exported.
                # Only a repaired, independently verifiable package may take a new identity.
                if old["integrity"] in (TRUSTED, LEGACY) and old["manifest_hash"]:
                    raise ContractError("验证包登记不能覆盖")
                connection.execute("UPDATE certification_bundles SET manifest_hash=? WHERE bundle_id=?",
                                   (manifest_hash, bundle_id))
                state = self._record_report(bundle_id, report, connection)
                return {"bundle_id": bundle_id, "case_id": case_id, "mapping_id": mapping_id,
                        "path": str(path), "manifest_hash": manifest_hash,
                        "integrity": state["status"], "trusted": state["trusted"]}
            connection.execute("INSERT INTO certification_bundles(bundle_id,case_id,mapping_id,path,manifest_hash) VALUES(?,?,?,?,?)",
                               (bundle_id, *values, manifest_hash))
            state = self._record_report(bundle_id, report, connection)
            return dict(connection.execute("SELECT * FROM certification_bundles WHERE bundle_id=?",
                                           (bundle_id,)).fetchone()) | {
                "integrity": state["status"], "trusted": state["trusted"]}

    def verify(self, bundle_id: str) -> dict[str, Any]:
        """Re-check a registered bundle; repeated calls are stable and audited."""
        row = self._row(bundle_id)
        if row is None:
            raise ContractError("验证包未登记")
        report = inspect_bundle(Path(row["path"]))
        with self.repository.transaction() as connection:
            return self._record_report(bundle_id, report, connection)

    def verify_all(self) -> list[dict[str, Any]]:
        results = []
        for row in self.list_registrations():
            results.append(self.verify(row["bundle_id"]))
        return results

    def refresh(self, bundle_id: str) -> dict[str, Any]:
        """Re-verify and allow a repaired package to regain a trusted registration."""
        row = self._row(bundle_id)
        if row is None:
            raise ContractError("验证包未登记")
        report = inspect_bundle(Path(row["path"]))
        if not report["usable"]:
            with self.repository.transaction() as connection:
                self._record_report(bundle_id, report, connection)
            raise ContractError("验证包完整性核验失败: " + ("; ".join(report["errors"]) or "验证包不完整"))
        manifest_hash = report.get("manifest_hash") or ""
        if manifest_hash != row["manifest_hash"] and row["integrity"] in (TRUSTED, LEGACY):
            with self.repository.transaction() as connection:
                self._record_report(bundle_id, report | {"errors": list(report["errors"]) +
                                                         ["manifest hash changed since registration"]},
                                    connection)
            raise ContractError("验证包清单已经改变")
        with self.repository.transaction() as connection:
            if manifest_hash != row["manifest_hash"]:
                connection.execute("UPDATE certification_bundles SET manifest_hash=? WHERE bundle_id=?",
                                   (manifest_hash, bundle_id))
            return self._record_report(bundle_id, report, connection)

    def list_registrations(self) -> list[dict[str, Any]]:
        with self.repository.connect() as connection:
            rows = connection.execute("SELECT * FROM certification_bundles ORDER BY bundle_id").fetchall()
        return [dict(row) for row in rows]

    def status(self, bundle_id: str) -> dict[str, Any] | None:
        row = self._row(bundle_id)
        return dict(row) if row else None

    def _evaluate(self, bundle_id: str):
        """Return (row, live report) without mutating state."""
        row = self._row(bundle_id)
        if row is None:
            raise ContractError("验证包未登记")
        return row, inspect_bundle(Path(row["path"]))

    def sign(self, certification_id: str, bundle_id: str):
        row = self._row(bundle_id)
        if row is None:
            raise ContractError("验证包未登记")
        report = inspect_bundle(Path(row["path"]))
        status = _status_for(report)
        if status == BLOCKED:
            with self.repository.transaction() as connection:
                self._record_report(bundle_id, report, connection)
            raise ContractError("验证包完整性核验失败，不能签发: " +
                                ("; ".join(report["errors"]) or "验证包不完整"))
        current = report.get("manifest_hash") or ""
        if current != row["manifest_hash"]:
            with self.repository.transaction() as connection:
                self._record_report(bundle_id, report | {"errors": ["manifest hash changed since registration"]},
                                    connection)
            raise ContractError("验证包清单已经改变")
        with self.repository.transaction() as connection:
            self._record_report(bundle_id, report, connection)
        # Block a pending conclusion if *any* registered material for this case is broken.
        for other in self.list_registrations():
            if other["bundle_id"] == bundle_id or other["case_id"] != row["case_id"]:
                continue
            other_report = inspect_bundle(Path(other["path"]))
            if _status_for(other_report) == BLOCKED:
                # Persist the breakage; the operator must resolve it explicitly.
                with self.repository.transaction() as connection:
                    self._record_report(other["bundle_id"], other_report, connection)
                raise ContractError("同一案例还有损坏的验证包: " + other["bundle_id"])
        evidence = {"bundle_id": bundle_id, "manifest_hash": current, "integrity": status,
                    "record_rows": report.get("record_rows"), "rule_rows": report.get("rule_rows")}
        return self.repository.sign_case(certification_id, row["case_id"], row["mapping_id"], evidence)

    # ----------------------------------------------------------- reuse controls
    def case_reuse(self, case_id: str) -> dict[str, Any]:
        """Whether a case's registered material may support pending reuse."""
        rows = [row for row in self.list_registrations() if row["case_id"] == case_id]
        bundles = []
        blocking: list[str] = []
        for row in rows:
            report = inspect_bundle(Path(row["path"]))
            status = _status_for(report)
            with self.repository.transaction() as connection:
                self._record_report(row["bundle_id"], report, connection)
            bundles.append({"bundle_id": row["bundle_id"], "status": status,
                            "errors": list(report["errors"]), "warnings": list(report["warnings"]),
                            "missing": list(report["missing"])})
            if status == BLOCKED:
                blocking.append(row["bundle_id"])
        return {"case_id": case_id, "reusable": not blocking and bool(bundles),
                "status": BLOCKED if blocking else (TRUSTED if any(
                    item["status"] == TRUSTED for item in bundles) else LEGACY),
                "requires_upgrade": any(item["status"] == LEGACY for item in bundles),
                "blocking_bundles": blocking, "bundles": bundles}

    def impact(self, mapping_id: str) -> dict[str, Any]:
        """Mapping impact enriched with the integrity risk of signed evidence."""
        report = self.repository.mapping_impact(mapping_id)
        risks = []
        with self.repository.connect() as connection:
            signed = connection.execute(
                "SELECT * FROM certifications WHERE mapping_id=? ORDER BY signed_at,certification_id",
                (mapping_id,)).fetchall()
        for row in signed:
            item = dict(row)
            bundle_id = item.get("bundle_id")
            if not bundle_id:
                try:
                    evidence = json.loads(item.get("evidence_json") or "{}")
                except json.JSONDecodeError:
                    evidence = {}
                bundle_id = evidence.get("bundle_id")
            registration = self.status(bundle_id) if bundle_id else None
            if registration is None:
                status, errors = UNKNOWN, []
            else:
                live = inspect_bundle(Path(registration["path"]))
                status, errors = _status_for(live), list(live["errors"])
            # Issued facts are preserved verbatim; only risk is appended.
            risks.append({"certification_id": item["certification_id"], "bundle_id": bundle_id,
                          "integrity": status, "at_risk": status == BLOCKED,
                          "unverified": status == UNKNOWN,
                          "errors": errors})
        report = dict(report)
        # Keep the historical mapping_impact shape intact while appending risk data.
        for item in report.get("signed_certifications", []):
            risk = next((entry for entry in risks
                         if entry["certification_id"] == item["certification_id"]), None)
            if risk is not None:
                item["integrity"] = risk["integrity"]
                item["at_risk"] = risk["at_risk"]
        report["integrity_risks"] = risks
        report["at_risk"] = any(item["at_risk"] for item in risks)
        report["unverified"] = any(item["unverified"] for item in risks)
        report["reusable"] = not report["at_risk"]
        return report

    def risks(self) -> list[dict[str, Any]]:
        findings = []
        for row in self.list_registrations():
            report = inspect_bundle(Path(row["path"]))
            status = _status_for(report)
            with self.repository.transaction() as connection:
                self._record_report(row["bundle_id"], report, connection)
            if status != TRUSTED:
                findings.append({"bundle_id": row["bundle_id"], "case_id": row["case_id"],
                                 "mapping_id": row["mapping_id"], "integrity": status,
                                 "requires_upgrade": status == LEGACY,
                                 "errors": list(report["errors"]),
                                 "warnings": list(report["warnings"])})
        return findings
