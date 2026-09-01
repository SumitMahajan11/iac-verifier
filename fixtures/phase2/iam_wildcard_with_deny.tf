resource "aws_iam_policy" "wildcard_with_deny" {
  name = "wildcard-with-deny-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = ["*"]
      },
      {
        Effect   = "Deny"
        Action   = ["*"]
        Resource = ["*"]
      }
    ]
  })
}
