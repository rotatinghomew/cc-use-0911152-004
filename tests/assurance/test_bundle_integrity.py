from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from standards_bridge.artifacts.conformance_report import export_bundle, inspect_bundle, verify_bundle
from standards_bridge.assurance.bundle_certifications import BLOCKED, LEGACY, TRUSTED, BundleCertifications
from standards_bridge.profiles.specification import ContractError, stable_hash
from standards_bridge.verification_hub import Application, run, verify

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "acceptance.json"


def write_legacy(root: Path, source: Path) -> None:
    """Dress a current bundle in the pre-pinning manifest format."""
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    legacy = {"files": manifest["files"], "record_rows": manifest["record_rows"],
              "rule_rows": manifest["rule_rows"], "created_at": manifest["created_at"]}
    legacy["manifest_hash"] = stable_hash(legacy)
    root.mkdir(parents=True, exist_ok=True)
    for name in ("summary.json", "decisions.json", "audit-events.json", "records.csv", "rules.csv"):
        shutil.copy(source / name, root / name)
    (root / "manifest.json").write_text(json.dumps(legacy), encoding="utf-8")


class BundleIntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "db"
        self.output = self.root / "out"
        run(FIXTURE, self.database, self.output)

    def test_delivered_details_statistics_and_evidence_agree(self):
        report = inspect_bundle(self.output)
        self.assertEqual(report["status"], "verified")
        self.assertTrue(report["trusted"])
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["record_rows"], 8)
        self.assertGreater(report["rule_rows"], 500)
        manifest = json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn("records.csv", manifest["artifacts"])
        self.assertIn("rules.csv", manifest["artifacts"])

    def test_missing_case_details_blocks_the_bundle(self):
        (self.output / "records.csv").unlink()
        report = inspect_bundle(self.output)
        self.assertEqual(report["status"], "corrupt")
        self.assertTrue(report["blocked"])
        self.assertIn("records.csv is missing", report["errors"])
        self.assertIn("records.csv", report["missing"])

    def test_missing_rule_evidence_blocks_the_bundle(self):
        (self.output / "rules.csv").unlink()
        report = inspect_bundle(self.output)
        self.assertTrue(report["blocked"])
        self.assertIn("rules.csv is missing", report["errors"])

    def test_partial_rewrite_of_details_is_detected(self):
        path = self.output / "rules.csv"
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[1] = lines[1].replace("True", "False", 1)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = inspect_bundle(self.output)
        self.assertTrue(report["blocked"])
        self.assertIn("rules.csv hash mismatch", report["errors"])

    def test_statistics_must_match_details_even_if_hashes_are_recomputed(self):
        # Forge a self-consistent manifest around a summary that disagrees with the details.
        summary = json.loads((self.output / "summary.json").read_text(encoding="utf-8"))
        summary["record_count"] = 999
        (self.output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        manifest = json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))
        manifest.pop("manifest_hash")
        manifest["files"]["summary.json"] = stable_hash(summary)
        manifest["manifest_hash"] = stable_hash(manifest)
        (self.output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        report = inspect_bundle(self.output)
        self.assertTrue(report["blocked"])
        self.assertIn("summary.json record_count does not match records.csv", report["errors"])

    def test_legacy_missing_details_is_distinguished_from_format_difference(self):
        legacy = self.root / "legacy"
        write_legacy(legacy, self.output)
        report = inspect_bundle(legacy)
        self.assertEqual(report["status"], "legacy")
        self.assertTrue(report["usable"])
        self.assertFalse(report["blocked"])
        self.assertTrue(any("does not pin" in warning for warning in report["warnings"]))
        (legacy / "rules.csv").unlink()
        broken = inspect_bundle(legacy)
        self.assertEqual(broken["status"], "corrupt")
        self.assertTrue(broken["blocked"])


class CertificationIntegrityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "db"
        self.output = self.root / "out"
        self.application = Application(self.database)
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.application.run_fixture(fixture, self.output)
        self.case = self.application.repository.list_records()[0].record_id
        self.application.repository.register_mapping("map", "source", "target", {})
        self.application.repository.link_case_mapping(self.case, "map")
        self.bundles = self.application.bundle_certifications

    def damage_details(self):
        path = self.output / "rules.csv"
        path.write_text(path.read_text(encoding="utf-8").replace("check_", "xheck_", 1), encoding="utf-8")

    def test_damaged_bundle_cannot_sign(self):
        self.bundles.register("b", self.case, "map", self.output)
        self.damage_details()
        with self.assertRaises(ContractError):
            self.bundles.sign("cert", "b")
        self.assertEqual(self.bundles.status("b")["integrity"], BLOCKED)

    def test_damage_is_persisted_and_blocks_reuse_and_pending_certification(self):
        self.bundles.register("b", self.case, "map", self.output)
        self.damage_details()
        reuse = self.bundles.case_reuse(self.case)
        self.assertFalse(reuse["reusable"])
        self.assertEqual(reuse["blocking_bundles"], ["b"])
        # Restart: the blocked state is durable, not just a one-off CLI error.
        restarted = BundleCertifications(Application(self.database).repository)
        self.assertEqual(restarted.status("b")["integrity"], BLOCKED)
        self.assertFalse(restarted.case_reuse(self.case)["reusable"])

    def test_repaired_bundle_regains_trust_and_can_sign(self):
        self.bundles.register("b", self.case, "map", self.output)
        good = (self.output / "rules.csv").read_bytes()
        self.damage_details()
        self.assertFalse(self.bundles.case_reuse(self.case)["reusable"])
        (self.output / "rules.csv").write_bytes(good)
        self.assertEqual(self.bundles.verify("b")["status"], TRUSTED)
        self.assertTrue(self.bundles.case_reuse(self.case)["reusable"])
        self.bundles.sign("cert", "b")

    def test_issued_facts_survive_later_damage_with_appended_risk(self):
        self.bundles.register("b", self.case, "map", self.output)
        signed = self.bundles.sign("cert", "b")
        self.damage_details()
        impact = self.bundles.impact("map")
        self.assertTrue(impact["at_risk"])
        self.assertEqual(impact["signed_certifications"][0]["certification_id"], "cert")
        self.assertEqual(impact["signed_certifications"][0]["signed_at"],
                         self.application.repository.certification("cert")["signed_at"])
        self.assertEqual(self.application.repository.certification("cert")["evidence_hash"],
                         signed["evidence_hash"])
        risk = {item["certification_id"]: item for item in impact["integrity_risks"]}
        self.assertTrue(risk["cert"]["at_risk"])
        self.assertEqual(risk["cert"]["integrity"], BLOCKED)

    def test_legacy_bundle_registers_and_records_format_difference(self):
        legacy = self.root / "legacy"
        write_legacy(legacy, self.output)
        result = self.bundles.register("old", self.case, "map", legacy)
        self.assertEqual(result["integrity"], LEGACY)
        self.assertTrue(result["trusted"])
        state = self.bundles.status("old")
        self.assertEqual(state["integrity"], LEGACY)
        self.assertTrue(json.loads(state["warnings_json"]))

    def test_legacy_bundle_losing_details_is_blocked(self):
        legacy = self.root / "legacy"
        write_legacy(legacy, self.output)
        self.bundles.register("old", self.case, "map", legacy)
        (legacy / "records.csv").unlink()
        with self.assertRaises(ContractError):
            self.bundles.sign("cert", "old")
        state = self.bundles.status("old")
        self.assertEqual(state["integrity"], BLOCKED)
        self.assertIn("records.csv", json.loads(state["errors_json"])[0])

    def test_registration_requires_intact_details(self):
        (self.output / "rules.csv").unlink()
        with self.assertRaises(ContractError):
            self.bundles.register("b", self.case, "map", self.output)

    def test_repeated_verification_is_stable_and_audited(self):
        self.bundles.register("b", self.case, "map", self.output)
        first = self.bundles.verify("b")
        second = BundleCertifications(Application(self.database).repository).verify("b")
        self.assertEqual(first["status"], second["status"])
        self.assertEqual(first["manifest_hash"], second["manifest_hash"])
        history = self.application.repository.snapshot()["counts"]["events"]
        self.bundles.verify("b")
        self.assertGreaterEqual(self.application.repository.snapshot()["counts"]["events"], history)

    def test_restart_preserves_signature_and_registered_manifest_identity(self):
        self.bundles.register("b", self.case, "map", self.output)
        signed = self.bundles.sign("cert", "b")
        restarted = BundleCertifications(Application(self.database).repository)
        self.assertEqual(restarted.sign("cert", "b")["evidence_hash"], signed["evidence_hash"])
        stored = restarted.status("b")
        self.assertEqual(stored["manifest_hash"], json.loads(stored["report_json"])["manifest_hash"])

    def test_verify_cli_reports_persisted_trust_state(self):
        self.bundles.register("b", self.case, "map", self.output)
        self.damage_details()
        self.bundles.verify("b")
        result = verify(self.database, self.output)
        self.assertFalse(result["ok"])
        self.assertEqual(result["bundle_status"], "corrupt")
        self.assertEqual(result["blocked_cases"], [self.case])
        self.assertTrue(result["integrity_risks"])


class RunConsistencyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "db"
        self.output = self.root / "out"

    def counts(self):
        return Application(self.database).repository.snapshot()["counts"]

    def test_repeated_runs_do_not_duplicate_the_case_ledger(self):
        run(FIXTURE, self.database, self.output)
        first = self.counts()
        run(FIXTURE, self.database, self.output)
        second = self.counts()
        self.assertEqual(first["records"], second["records"])
        self.assertEqual(first["decisions"], second["decisions"])
        self.assertEqual(first["record_versions"], second["record_versions"])

    def test_rebuild_after_lost_output_reuses_ledger_facts(self):
        run(FIXTURE, self.database, self.output)
        first = self.counts()
        shutil.rmtree(self.output)
        result = run(FIXTURE, self.database, self.output)
        self.assertEqual(result["records"], 8)
        self.assertEqual(self.counts()["decisions"], first["decisions"])
        self.assertEqual(self.counts()["record_versions"], first["record_versions"])
        self.assertEqual(verify_bundle(self.output), [])


if __name__ == "__main__":
    unittest.main()
