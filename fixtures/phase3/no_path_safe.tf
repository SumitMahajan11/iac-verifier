resource "aws_iam_role" "safe_role_a" {
  name = "safe_role_a"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::111122223333:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "safe_policy_a" {
  name = "safe_policy_a"
  role = aws_iam_role.safe_role_a.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "s3:ListBucket"
        Resource = "arn:aws:s3:::my-bucket"
      }
    ]
  })
}

resource "aws_iam_role" "isolated_role_b" {
  name = "isolated_role_b"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::444455556666:root"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "isolated_policy_b" {
  name = "isolated_policy_b"
  role = aws_iam_role.isolated_role_b.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "ec2:DescribeInstances"
        Resource = "arn:aws:ec2:us-east-1:123456789012:instance/i-12345678"
      }
    ]
  })
}
