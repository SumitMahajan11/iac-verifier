import json
import sys
from checkov.common.runners.runner_registry import RunnerRegistry
from checkov.runner_filter import RunnerFilter
from checkov.terraform.runner import Runner as TfRunner

files = [
    "fixtures/phase2/sg_open_ssh.tf",
    "fixtures/phase2/sg_restricted_ssh.tf",
    "fixtures/phase2/iam_wildcard_allow.tf",
    "fixtures/phase2/iam_wildcard_with_deny.tf",
    "fixtures/phase3/direct_escalation.tf",
    "fixtures/phase3/no_path_safe.tf",
    "fixtures/phase3/unresolved_trust.tf",
    "fixtures/corpora/terragoat/terraform/aws/ec2.tf",
    "fixtures/corpora/sadcloud/modules/aws/iam/main.tf",
    "fixtures/corpora/sadcloud/modules/aws/ec2/main.tf"
]

runner = TfRunner()
report = runner.run(root_folder=None, files=files, runner_filter=RunnerFilter())
summary = report.get_summary()

failed_checks = []
for record in report.failed_checks:
    failed_checks.append({
        "check_id": record.check_id,
        "check_name": record.check_name,
        "file_path": record.file_path,
        "resource": record.resource,
        "guideline": record.guideline
    })

passed_checks = []
for record in report.passed_checks:
    passed_checks.append({
        "check_id": record.check_id,
        "check_name": record.check_name,
        "file_path": record.file_path,
        "resource": record.resource
    })

results = {
    "summary": summary,
    "failed_checks_count": len(failed_checks),
    "passed_checks_count": len(passed_checks),
    "failed_sample": failed_checks[:10],
    "passed_sample": passed_checks[:10]
}

with open("scratch/checkov_summary.json", "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print("Checkov scan complete! Summary:")
print(json.dumps(summary, indent=2))
