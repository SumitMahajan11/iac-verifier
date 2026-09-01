# Adversarial Fixture 2: Multiple Independent Minimal Fixes & Deterministic Selection
# Policy 1 has statement 0 (wildcard allow) and statement 1 (scoped safe allow). Deleting statement 0 restores UNSAT.
# Policy 2 has statement 0 (scoped safe allow) and statement 1 (wildcard allow). Deleting statement 1 restores UNSAT.
# Tests that single-statement minimal fixes are correctly isolated and deterministically selected.

resource "aws_iam_policy" "policy_1" {
  name = "policy_1"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = ["*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::bucket/*"]
      }
    ]
  })
}

resource "aws_iam_policy" "policy_2" {
  name = "policy_2"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances"]
        Resource = ["arn:aws:ec2:us-east-1:123456789012:instance/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = ["*"]
      }
    ]
  })
}
