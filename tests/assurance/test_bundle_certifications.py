import json,tempfile,unittest
from pathlib import Path
from standards_bridge.verification_hub import Application
from standards_bridge.profiles.specification import ContractError

class BundleCertificationTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.a=Application(self.root/'db');f=json.loads(Path('fixtures/acceptance.json').read_text())
        self.a.run_fixture(f,self.root/'out');self.case=self.a.repository.list_records()[0].record_id
        self.a.repository.register_mapping('map','source','target',{})
        self.a.repository.link_case_mapping(self.case,'map')
    def test_valid_bundle_signs_and_restart_preserves_history(self):
        b=self.a.bundle_certifications;b.register('b',self.case,'map',self.root/'out')
        signed=b.sign('cert','b');self.assertEqual(signed['case_id'],self.case)
        self.assertEqual(Application(self.root/'db').bundle_certifications.sign('cert','b'),signed)
    def test_replacing_registered_manifest_prevents_new_signature(self):
        b=self.a.bundle_certifications;b.register('b',self.case,'map',self.root/'out')
        path=self.root/'out/manifest.json';m=json.loads(path.read_text());m['extra']='changed';path.write_text(json.dumps(m))
        with self.assertRaises(ContractError):b.sign('cert','b')
    def test_unknown_case_rejected(self):
        with self.assertRaises(ContractError):self.a.bundle_certifications.register('b','missing','map',self.root/'out')
