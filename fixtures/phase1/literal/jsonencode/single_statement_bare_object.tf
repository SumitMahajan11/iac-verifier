resource "aws_iam_policy" "bare_object" {
  name = "bare-object-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = {
      Effect   = "Allow"
      Action   = ["s3:ListBucket"]
      Resource = ["arn:aws:s3:::my-bucket"]
    }
  })
}
