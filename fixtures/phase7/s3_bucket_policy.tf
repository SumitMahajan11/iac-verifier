resource "aws_s3_bucket_policy" "wildcard_sat" {
  bucket = "my-bucket"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
        Principal = "*"
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "scoped_unsat" {
  bucket = "my-bucket"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::my-bucket/*"
        Principal = "*"
      }
    ]
  })
}
