resource "aws_iam_policy" "normalization" {
  name = "normalization-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::my-bucket/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket2/*"]
      }
    ]
  })
}
