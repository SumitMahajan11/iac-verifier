
resource "aws_iam_role" "b" {
  name = "role_b"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123:root"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "a" {
  name   = "policy_a"
  role   = aws_iam_role.b.id
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
EOF
}
