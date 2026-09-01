resource "aws_iam_policy" "wildcard_allow" {
  name = "wildcard-allow-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = ["*"]
      }
    ]
  })
}
