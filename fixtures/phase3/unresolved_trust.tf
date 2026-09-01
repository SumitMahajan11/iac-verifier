resource "aws_iam_role" "unresolved_trust_role" {
  name = "unresolved_trust_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "module.unparsed_module.role_arn"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name = "admin_policy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = "*"
          Resource = "*"
        }
      ]
    })
  }
}
