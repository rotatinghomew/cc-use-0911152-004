"""验证包登记与认证签发使用项目的正式包校验入口。"""
import json
from pathlib import Path
from standards_bridge.profiles.specification import ContractError,stable_hash
from standards_bridge.artifacts.conformance_report import verify_bundle

class BundleCertifications:
    def __init__(self,repository):
        self.repository=repository
        with repository.connect() as c:c.execute("CREATE TABLE IF NOT EXISTS certification_bundles(bundle_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,mapping_id TEXT NOT NULL,path TEXT NOT NULL,manifest_hash TEXT NOT NULL)")

    def register(self,bundle_id,case_id,mapping_id,path):
        path=Path(path).resolve()
        errors=verify_bundle(path)
        if errors:raise ContractError('; '.join(errors))
        manifest_hash=stable_hash(json.loads((path/'manifest.json').read_text()))
        with self.repository.transaction() as c:
            if not c.execute("SELECT 1 FROM records WHERE record_id=?",(case_id,)).fetchone():raise ContractError("案例不存在")
            old=c.execute("SELECT * FROM certification_bundles WHERE bundle_id=?",(bundle_id,)).fetchone()
            value=(case_id,mapping_id,str(path),manifest_hash)
            if old:
                if tuple(old[k] for k in ['case_id','mapping_id','path','manifest_hash'])!=value:raise ContractError("验证包登记不能覆盖")
                return dict(old)
            c.execute("INSERT INTO certification_bundles VALUES(?,?,?,?,?)",(bundle_id,*value))
            return dict(c.execute("SELECT * FROM certification_bundles WHERE bundle_id=?",(bundle_id,)).fetchone())

    def sign(self,certification_id,bundle_id):
        with self.repository.connect() as c:row=c.execute("SELECT * FROM certification_bundles WHERE bundle_id=?",(bundle_id,)).fetchone()
        if row is None:raise ContractError("验证包未登记")
        errors=verify_bundle(Path(row['path']))
        if errors:raise ContractError('; '.join(errors))
        current=stable_hash(json.loads((Path(row['path'])/'manifest.json').read_text()))
        if current!=row['manifest_hash']:raise ContractError("验证包清单已经改变")
        return self.repository.sign_case(certification_id,row['case_id'],row['mapping_id'],{'bundle_id':bundle_id,'manifest_hash':current})
