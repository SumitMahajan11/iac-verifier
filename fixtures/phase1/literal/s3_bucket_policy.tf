resource "aws_s3_bucket" "logs_bucket" {
  bucket = "my-corporate-logs-bucket"
}

resource "aws_s3_bucket_policy" "logs_policy" {
  bucket = "my-corporate-logs-bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::my-corporate-logs-bucket/*"
      }
    ]
  })
}
