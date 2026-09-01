resource "aws_iam_policy" "multi_stmt" {
  name = "multi-statement-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::my-bucket/*"]
      },
      {
        Effect   = "Deny"
        Action   = ["s3:DeleteBucket"]
        Resource = ["arn:aws:s3:::my-bucket"]
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage", "sqs:ReceiveMessage"]
        Resource = ["arn:aws:sqs:us-east-1:123456789012:my-queue"]
      }
    ]
  })
}
