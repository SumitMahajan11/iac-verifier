import json
from checkov.runner_filter import RunnerFilter
from checkov.terraform.runner import Runner as TfRunner

files = [
    "fixtures/phase2/iam_wildcard_with_deny.tf",
    "fixtures/phase3/direct_escalation.tf",
    "fixtures/phase3/no_path_safe.tf"
]

runner = TfRunner()
report = runner.run(root_folder=None, files=files, runner_filter=RunnerFilter())

print("=== CHECKOV FINDINGS FOR iam_wildcard_with_deny.tf ===")
for r in report.failed_checks:
    if "iam_wildcard_with_deny.tf" in r.file_path:
        print(f"FAILED CHECK: {r.check_id} - {r.check_name} on {r.resource}")

for r in report.passed_checks:
    if "iam_wildcard_with_deny.tf" in r.file_path:
        print(f"PASSED CHECK: {r.check_id} - {r.check_name} on {r.resource}")

print("\n=== CHECKOV FINDINGS FOR PRIVILEGE ESCALATION (direct_escalation / no_path_safe) ===")
for r in report.failed_checks:
    if "phase3" in r.file_path:
        print(f"FAILED CHECK: {r.check_id} - {r.check_name} on {r.file_path} ({r.resource})")
