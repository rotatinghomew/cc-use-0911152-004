中国—东盟人工智能标准适配验证台

映射与认证：Repository.register_mapping 维护规格对照和单调修订号，
link_case_mapping 登记案例使用的映射，sign_case 基于当时映射版本和证据
封存签发结论，mapping_impact 可读出影响案例和历史签发。签发记录不能被
后续映射修订覆盖。

运行验收：
python3 -m standards_bridge run --fixture fixtures/acceptance.json --database /tmp/standards_bridge.sqlite3 --output /tmp/standards_bridge-output

核验：
python3 -m standards_bridge verify --database /tmp/standards_bridge.sqlite3 --output /tmp/standards_bridge-output

全量测试：
python3 -m unittest discover -s tests -v

按模块测试：
python3 -m unittest tests.profiles.test_specification -v

构建检查：
python3 -m compileall -q standards_bridge tests

bundle_certifications.register 关联案例、映射与正式验证包；sign 调用正式包核验后签发认证，保留登记时清单身份，已签发记录不可覆盖。

验证包完整性：manifest 固定 summary/decisions/audit-events 的内容哈希，并用
artifacts（records.csv、rules.csv 的内容哈希与行数）固定案例明细和规则结果；
inspect_bundle 再把明细、统计与依据互相核对（记录数、结论、分数、规则条数、
行数、审计链）。任何缺失、哈希不符或交叉核对失败都会把包持久化为 blocked，
阻止该包继续支撑待认证或待复用结论，而不仅是命令行多报一条错误。
旧版清单若未固定明细，只要有明细且能核对，则记为 legacy（格式差异，可复用、
需升级），与确属缺失区分；已签发认证事实保留，包后来损坏只在 impact/risks
中追加风险。verify 子命令返回 bundle_status、blocked_cases 与 integrity_risks，
存在损坏登记时退出码为非零。修复后的包通过 register/verify/refresh 重新取得
可信状态。run 按案例原子提交，重复核验、部分写入与服务重启都不会让案例账本
与复用结论漂移。
