data "aws_organizations_organization" "awsorg" {}

data "aws_caller_identity" "current" {}

data "aws_organizations_organization" "security_account" {}

locals {
  security_account = [for x in data.aws_organizations_organization.security_account.non_master_accounts : x.id if x.name == "security"][0]
}
