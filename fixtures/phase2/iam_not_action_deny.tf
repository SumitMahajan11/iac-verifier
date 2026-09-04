resource "aws_iam_role_policy" "not_action_deny_policy" {
  name = "not-action-deny-policy"
  role = "test-role"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    },
    {
      "Effect": "Deny",
      "NotAction": [
        "s3:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}
