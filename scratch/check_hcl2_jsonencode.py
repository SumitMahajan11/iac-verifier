import hcl2
from io import StringIO

def parse_hcl_arg(arg_str):
    fake_hcl = f"temp = {arg_str}\n"
    try:
        res = hcl2.load(StringIO(fake_hcl))
        return res.get("temp")
    except Exception as e:
        print("Failed to parse via hcl2:", e)
        return None

arg3 = '{Version = "2012-10-17", Statement = [{Effect = "Allow", Action = "s3:GetObject", Resource = data.aws_iam_policy_document.external.json}]}'
print("Parsed Arg 3 (Data source ref):", parse_hcl_arg(arg3))

arg4 = '{Version = "2012-10-17", Statement = [{Effect = "Allow", Action = "s3:GetObject", Resource = var.unresolved_var}]}'
print("Parsed Arg 4 (Unresolved var):", parse_hcl_arg(arg4))
