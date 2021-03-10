# The following permissions are required

Enable SecurityHub

```JSON
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "mappedc123208",
            "Action": "securityhub:EnableSecurityHub",
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Sid": "mapped9e94f7b",
            "Action": "securityhub:BatchEnableStandards",
            "Resource": "arn:aws:securityhub:ca-central-1::standards/aws-foundational-security-best-practices/v/1.0.0",
            "Effect": "Allow"
        },
        {
            "Sid": "unmappedactions",
            "Action": [
                "securityhub:ListEnabledProductsForImport",
                "securityhub:ListMembers",
                "securityhub:GetFindings",
                "securityhub:GetInsights"
            ],
            "Resource": "*",
            "Effect": "Allow"
        }
    ]
}

```