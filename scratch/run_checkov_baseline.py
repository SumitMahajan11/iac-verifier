import subprocess
import json

files_to_check = [
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

cmd = [".venv/Scripts/python.exe", "-c", "import sys; from checkov.main import Checkov; sys.argv=['checkov', '-o', 'json', '--compact'] + " + str(files_to_check) + "; Checkov().run()"]

res = subprocess.run(cmd, capture_output=True, text=True)
with open("scratch/checkov_raw.json", "w", encoding="utf-8") as f:
    f.write(res.stdout)
print("Checkov raw stdout written to scratch/checkov_raw.json. Returncode:", res.returncode)
