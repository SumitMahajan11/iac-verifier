resource "aws_iam_policy" "unresolved_mixed" {
  name = "unresolved-mixed-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::my-bucket/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = data.aws_iam_policy_document.external.json
      }
    ]
  })
}
