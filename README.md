# Compliance Monitoring Solution

[[_TOC_]]

## Summary

The OCC Compliance Monitoring Solution is deployed to include the following primary services;
  + AWS Config - Rules based on NIST 800-53 with customized definitions
  + Security Hub
  + Parameter Store
  + Lambda Function - Forwards AWS Config changes to Security Hub and assigns Severity
  + Lambda Function - Enables Organizational Delegated Administration to 'Security' account

![Compliance Monitoring Solution](./images/nist_compliance_monitoring_solution_overview.png)

### Components

#### Order of operations

+ Validation that Security Hub is *NOT* enabled in any AWS Accounts
+ Validation that Organizational Service Control Policies permit the Security Hub actions
+ Terraform parameter configuration
+ Creation of CodePipeline artifact from ./src folder into ./artifacts folder
+ Creation of Lambda Forwarder artifact from ./src folder into ./artifacts folder
+ Deployment of Terraform Code

#### IaC Templates

| Short Name | Type | Purpose | filename |
| --- | --- |--- | --- |

#### CloudFormation StackSets

AWS CloudFormation StackSets enables you to create, update, or delete stacks across multiple AWS accounts and AWS Regions with a single operation. StackSets integration with AWS Organizations enables you to create stack sets with service-managed permissions, using a service-linked role that has the relevant permission in each member account. This lets you deploy stack instances to member accounts in your organization. You don't have to create the necessary AWS Identity and Access Management roles; StackSets creates the IAM role in each member account on your behalf. You can also choose to enable automatic deployments to accounts that are added to your organization in the future.

With trusted access between StackSets and Organizations enabled, the management account has permissions to create and manage stack sets for your organization. The management account can register up to five member accounts as delegated administrators. With trusted access enabled, delegated administrators also have permissions to create and manage stack sets for your organization. Stack sets with service-managed permissions are created in the management account, including stack sets that are created by delegated administrators. 

Our deployment via CloudFormation StackSets, against the Organization Root, enables a simplistic 'set-it-and-forget-it' approach for deployment.  StackSets will be deployed to existing AWS Accounts, and any additional AWS Accounts that are creaeted or onboarded to the Organization.

### AWS Config Rules

The AWS Config Rules are derived from the NIST 800-53 Conformance Pack.  By default there are no severity mappings available with AWS Config Rules, so we create a suffix with the severity.

Our naming convention introduces a prefix to define the rule type, and a suffix to define the severity.

![Config Rule Naming Convention](./images/awsconfig_naming_convention.png)

The AWS Config Rules that are deployed are visible to roles that have permissions to work with AWS Config Rules.

![NIST Config Rules](./images/awsconfig00.png)

### Security Hub

The Security Hub is configured to display dashboard based reports of Findings from default conformance packs.  The default packs can be utilised, but we supply a custom template replacing them to integrate findings from the Config Rules with specific tags to allocate them as NIST validations.

The Security Hub dashboard allows us to easily filter the Findings based on parameters, including the 'Starts with' filter to select 'nist-' only rules.

![Security Hub Dashboard](./images/awssecurityhub00.png)

Additional dashboarding can be created, for example reporting on findings by 'Severity.'

![NIST Compliance Dashboard Severity](./images/aws_securityhub_dashboard.png)

#### Aggregated View

The Security Hub Service utilises the AWS Organizations service to provide an aggregated view of ALL AWS Account Security Hub findings from the Security Account.  This provides the SecOps team with a consolidated dashboard across the entire AWS Landing Zone for all security findings.  Implementation within the Security Account provides a level of abstracted access that can only be accessed from SecOps roles with valid permissions.

![Consolidated Dashboard](./images/aws_securityhub_accounts.png)

## Deployment Process

As of Terraform 0.15, CloudFormation StackSets cannot be deployed against either OU or ROOT ids using AWS Organizations, and only iteratively against an expanding list of known accounts.  Whilst our preferred method of resource management and deployment is Terraform, utilizing just Terraform would require continuous running of the code to detect new accounts, and potential gaps in coverage between AWS Account creation and solution deployment.

The deployment of StackSets against AWS Organizations is moved into a Terraform managed CodePipeline, with discrete stages for each of the types of components deployed.  This enables us a more granular method of management of the solution and the ability to deploy change with small targeted updates made only within the Pipeline steps with chage, whilst the steps that remain the same execute with no change required.

![Implementation Design](.images/../images/Implementation_Design.png)

## Appendices

### Deployed Config Rule List
| SA&A  Compliance Guidance                                    | DeployedRuleName                                             |
| :--- | :--- |
| The credentials are audited for  authorized devices, users, and processes by ensuring IAM access keys are  rotated as per organizational policy. | nist-access-keys-rotated                                   |
| Ensure network integrity is protected by  ensuring X509 certificates are issued by AWS ACM. These certificates must be  valid and unexpired. | nist-acm-certificate-expiration-check                      |
| Ensure that your Elastic Load Balancers  (ELB) are configured to drop http headers. Because sensitive data can exist,  enable encryption in transit to help protect that data. | nist-alb-http-drop-invalid-header-enabled                  |
| To help protect data in transit, ensure  that your Application Load Balancer automatically redirects unencrypted HTTP  requests to HTTPS. Because sensitive data can exist, enable encryption in  transit to help protect that data. | nist-alb-http-to-https-redirection-check                   |
| Ensure AWS WAF is enabled on Elastic Load  Balancers (ELB) to help protect web applications. A WAF helps to protect your  web applications or APIs against common web exploits. | nist-alb-waf-enabled                                       |
| To help protect data at rest, ensure  encryption is enabled for your API Gateway stage's cache. Because sensitive  data can be captured for the API method, enable encryption at rest to help  protect that data. | nist-api-gw-cache-enabled-and-encrypted                    |
| API Gateway logging displays detailed  views of users who accessed the API and the way they accessed the API. This  insight enables visibility of user activities. | nist-api-gw-execution-logging-enabled                      |
| The Elastic Load Balancer (ELB) health  checks for Amazon Elastic Compute Cloud (Amazon EC2) Auto Scaling groups  support maintenance of adequate capacity and availability. | nist-autoscaling-group-elb-healthcheck-required            |
| Use Amazon CloudWatch to centrally  collect and manage log event activity. Inclusion of AWS CloudTrail data  provides details of API call activity within your AWS account. | nist-cloud-trail-cloud-watch-logs-enabled                  |
| Because sensitive data may exist and to  help protect data at rest, ensure encryption is enabled for your AWS  CloudTrail trails. | nist-cloud-trail-encryption-enabled                        |
| Utilize AWS CloudTrail log file  validation to check the integrity of CloudTrail logs. Log file validation  helps determine if a log file was modified or deleted or unchanged after  CloudTrail delivered it. | nist-cloud-trail-log-file-validation-enabled               |
| AWS CloudTrail can help in  non-repudiation by recording AWS Management Console actions and API calls.  You can identify the users and AWS accounts that called an AWS service, the  source IP address where the calls generated, and the timings of the calls. | nist-cloudtrail-enabled                                    |
| The collection of Simple Storage Service  (Amazon S3) data events helps in detecting any anomalous activity. The  details include AWS account information that accessed an Amazon S3 bucket, IP  address, and time of event. | nist-cloudtrail-s3-dataevents-enabled                      |
| This rule helps ensure the use of AWS  recommended security best practices for AWS CloudTrail, by checking for the  enablement of multiple settings. These include the use of log encryption, log  validation, and enabling AWS CloudTrail in multiple regions. | nist-cloudtrail-security-trail-enabled                     |
| Amazon CloudWatch alarms alert when a  metric breaches the threshold for a specified number of evaluation periods.  The alarm performs one or more actions based on the value of the metric or  expression relative to a threshold over a number of time periods. | nist-cloudwatch-alarm-action-check                         |
| To help protect sensitive data at rest,  ensure encryption is enabled for your Amazon CloudWatch Log Groups. | nist-cloudwatch-log-group-encrypted                        |
| Enable key rotation to ensure that keys  are rotated once they have reached the end of their crypto period. | nist-cmk-backing-key-rotation-enabled                      |
| Ensure authentication credentials  AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY do not exist within AWS Codebuild  project environments. Do not store these variables in clear text. | nist-codebuild-project-envvar-awscred-check                |
| Ensure the GitHub or Bitbucket source  repository URL does not contain personal access tokens, user name and  password within AWS Codebuild project environments. | nist-codebuild-project-source-repo-url-check               |
| Ensure a minimum duration of event log  data is retained for your log groups to help with troubleshooting and  forensics investigations. The lack of available past event log data makes it  difficult to reconstruct and identify potentially malicious events. | nist-cw-loggroup-retention-period-check                    |
| The backup feature of Amazon RDS creates  backups of your databases and transaction logs. Amazon RDS automatically  creates a storage volume snapshot of your DB instance, backing up the entire  DB instance. | nist-db-instance-backup-enabled                            |
| Manage access to the AWS Cloud by  ensuring DMS replication instances cannot be publicly accessed. DMS  replication instances can contain sensitive information and access control is  required for such accounts. | nist-dms-replication-not-public                            |
| Amazon DynamoDB auto scaling uses the AWS  Application Auto Scaling service to adjust provisioned throughput capacity  that automatically responds to actual traffic patterns. | nist-dynamodb-autoscaling-enabled                          |
| To help with data back-up processes,  ensure your Amazon DynamoDB tables are a part of an AWS Backup plan. AWS  Backup is a fully managed backup service with a policy-based backup solution. | nist-dynamodb-in-backup-plan                               |
| Enable this rule to check that  information has been backed up. It also maintains the backups by ensuring  that point-in-time recovery is enabled in Amazon DynamoDB. The recovery  maintains continuous backups of your table for the last 35 days. | nist-dynamodb-pitr-enabled                                 |
| Ensure that encryption is enabled for  your Amazon DynamoDB tables. Because sensitive data can exist at rest in  these tables, enable encryption at rest to help protect that data. | nist-dynamodb-table-encrypted-kms                          |
| To help with data back-up processes,  ensure your Amazon Elastic Block Store (Amazon EBS) volumes are a part of an  AWS Backup plan. AWS Backup is a fully managed backup service with a  policy-based backup solution. | nist-ebs-in-backup-plan                                    |
| Manage access to the AWS Cloud by  ensuring EBS snapshots are not publicly restorable. EBS volume snapshots can  contain sensitive information and access control is required for such  accounts. | nist-ebs-snapshot-public-restorable-check                  |
| To help protect data at rest, ensure that  encryption is enabled for your Amazon Elastic Block Store (Amazon EBS)  volumes. Because sensitive data can exist at rest in these volumes, enable  encryption at rest to help protect that data. | nist-ec2-ebs-encryption-by-default                         |
| Ensure the Instance Metadata Service  Version 2 (IMDSv2) method is enabled to help protect access and control of  Amazon Elastic Compute Cloud (Amazon EC2) instance metadata. | nist-ec2-imdsv2-check                                      |
| Enable this rule to help improve Amazon  Elastic Compute Cloud (Amazon EC2) instance monitoring on the Amazon EC2  console, which displays monitoring graphs with a 1-minute period for the  instance. | nist-ec2-instance-detailed-monitoring-enabled              |
| An inventory of the software platforms  and applications within the organization is possible by managing Amazon  Elastic Compute Cloud (Amazon EC2) instances with AWS Systems Manager. | nist-ec2-instance-managed-by-systems-manager               |
| Manage access to the AWS Cloud by  ensuring Amazon Elastic Compute Cloud (Amazon EC2) instances cannot be  publicly accessed. Amazon EC2 instances can contain sensitive information and  access control is required for such accounts. | nist-ec2-instance-no-public-ip                             |
| Deploy Elastic Compute Cloud (EC2)  instances within an Virtual Private Cloud (VPC) to enable secure  communication between an instance and other services within the amazon VPC,  without requiring an internet gateway, NAT device, or VPN connection. | nist-ec2-instances-in-vpc                                  |
| Use AWS Systems Manager Associations to  help with inventory of software platforms and applications within an  organization. | nist-ec2-managedinstance-association-compliance-status-check |
| Enable this rule to help with  identification and documentation of Amazon Elastic Compute Cloud (Amazon EC2)  vulnerabilities. | nist-ec2-managedinstance-patch-compliance-status-check     |
| Enable this rule to help with the  baseline configuration of Elastic Compute Cloud (Amazon EC2) instances by  checking whether Amazon EC2 instances have been stopped for more than the  allowed number of days, according to your organization's standards. | nist-ec2-stopped-instance                                  |
| This rule ensures that Amazon Elastic  Block Store volumes that are attached to Amazon Elastic Compute Cloud (Amazon  EC2) instances are marked for deletion when an instance is terminated. | nist-ec2-volume-inuse-check                                |
| Because sensitive data can exist and to  help protect data at rest, ensure encryption is enabled for your Amazon  Elastic File System (EFS). | nist-efs-encrypted-check                                   |
| To help with data back-up processes,  ensure your Amazon Elastic File System (Amazon EFS) file systems are a part  of an AWS Backup plan. AWS Backup is a fully managed backup service with a  policy-based backup solution. | nist-efs-in-backup-plan                                    |
| When automatic backups are enabled,  Amazon ElastiCache creates a backup of the cluster on a daily basis. The  backup can be retained for a number of days as specified by your  organization. Automatic backups can help guard against data loss. | nist-elasticache-redis-cluster-automatic-backup-check      |
| Because sensitive data can exist and to  help protect data at rest, ensure encryption is enabled for your Amazon  Elasticsearch Service (Amazon ES) domains. | nist-elasticsearch-encrypted-at-rest                       |
| Manage access to the AWS Cloud by  ensuring Amazon Elasticsearch Service (Amazon ES) Domains are within an  Amazon Virtual Private Cloud (Amazon VPC). | nist-elasticsearch-in-vpc-only                             |
| Ensure node-to-node encryption for Amazon  Elasticsearch Service is enabled. Node-to-node encryption enables TLS 1.2  encryption for all communications within the Amazon Virtual Private Cloud  (Amazon VPC). | nist-elasticsearch-node-to-node-encryption-check           |
| Because sensitive data can exist and to  help protect data at transit, ensure encryption is enabled for your Elastic  Load Balancing. | nist-elb-acm-certificate-required                          |
| Enable cross-zone load balancing for your  Elastic Load Balancers (ELBs) to help maintain adequate capacity and  availability. The cross-zone load balancing reduces the need to maintain  equivalent numbers of instances in each enabled availability zone. | nist-elb-cross-zone-load-balancing-enabled                 |
| This rule ensures that Elastic Load  Balancing has deletion protection enabled. Use this feature to prevent your  load balancer from being accidentally or maliciously deleted, which can lead  to loss of availability for your applications. | nist-elb-deletion-protection-enabled                       |
| Elastic Load Balancing activity is a  central point of communication within an environment. Ensure ELB logging is  enabled. The collected data provides detailed information about requests sent  to the ELB. | nist-elb-logging-enabled                                   |
| Ensure that your Elastic Load Balancers  (ELBs) are configured with SSL or HTTPS listeners. Because sensitive data can  exist, enable encryption in transit to help protect that data. | nist-elb-tls-https-listeners-only                          |
| The access permissions and authorizations  can be managed and incorporated with the principles of least privilege and  separation of duties, by enabling Kerberos for Amazon EMR clusters. | nist-emr-kerberos-enabled                                  |
| Manage access to the AWS Cloud by  ensuring Amazon EMR cluster master nodes cannot be publicly accessed. Amazon  EMR cluster master nodes can contain sensitive information and access control  is required for such accounts. | nist-emr-master-no-public-ip                               |
| Because senstive data can exist and to  help protect data at rest, ensure encryption is enabled for your Amazon  Elastic Block Store (Amazon EBS) volumes. | nist-encrypted-volumes                                     |
| Amazon GuardDuty can help to monitor and  detect potential cybersecurity events by using threat intelligence  feeds. | nist-guardduty-enabled-centralized                         |
| Amazon GuardDuty helps you understand the  impact of an incident by classifying findings by severity: low, medium, and  high. You can use these classifications for determining remediation  strategies and priorities. | nist-guardduty-non-archived-findings                       |
| AWS Identity and Access Management (IAM)  can help you incorporate the principles of least privilege and separation of  duties with access permissions and authorizations, by ensuring that IAM  groups have at least one IAM user. | nist-iam-group-has-users-check                             |
| Ensure an AWS Identity and Access  Management (IAM) user, IAM role or IAM group does not have an inline policy  to control access to systems and assets. AWS recommends to use managed  policies instead of inline policies. | nist-iam-no-inline-policy-check                            |
| The identities and the credentials are  issued, managed, and verified based on an organizational IAM password  policy. | nist-iam-password-policy                                   |
| AWS Identity and Access Management (IAM)  can help you incorporate the principles of least privilege with access  permissions and authorizations, restricting policies from containing  "Effect": "Allow" with "Action": "*"  over "Resource": "*". | nist-iam-policy-no-statements-with-admin-access            |
| Access to systems and assets can be  controlled by checking that the root user does not have access keys attached  to their AWS Identity and Access Management (IAM) role. Ensure that the root  access keys are deleted. | nist-iam-root-access-key-check                             |
| AWS Identity and Access Management (IAM)  can help you restrict access permissions and authorizations, by ensuring IAM  users are members of at least one group. | nist-iam-user-group-membership-check                       |
| Enable this rule to restrict access to  resources in the AWS Cloud. This rule ensures multi-factor authentication  (MFA) is enabled for all IAM users. MFA adds an extra layer of protection on  top of a user name and password. | nist-iam-user-mfa-enabled                                  |
| This rule ensures AWS Identity and Access  Management (IAM) policies are attached only to groups or roles to control  access to systems and assets. | nist-iam-user-no-policies-check                            |
| AWS Identity and Access Management (IAM)  can help you with access permissions and authorizations by checking for IAM  passwords and access keys that are not used for a specified time period. | nist-iam-user-unused-credentials-check                     |
| Manage access to resources in the AWS  Cloud by ensuring that internet gateways are only attached to authorized  Amazon Virtual Private Cloud (Amazon VPC). | nist-internet-gateway-authorized-vpc-only                  |
| To help protect data at rest, ensure  necessary customer master keys (CMKs) are not scheduled for deletion in AWS  Key Management Service (AWS KMS). | nist-kms-cmk-not-scheduled-for-deletion                    |
| Manage access to resources in the AWS  Cloud by ensuring AWS Lambda functions cannot be publicly accessed. Public  access can potentially lead to degradation of availability of resources. | nist-lambda-function-public-access-prohibited              |
| Deploy AWS Lambda functions within an  Amazon Virtual Private Cloud (Amazon VPC) for a secure communication between  a function and other services within the Amazon VPC. | nist-lambda-inside-vpc                                     |
| Manage access to resources in the AWS  Cloud by ensuring that MFA is enabled for all AWS Identity and Access  Management (IAM) users that have a console password. MFA adds an extra layer  of protection on top of a user name and password. | nist-mfa-enabled-for-iam-console-access                    |
| AWS CloudTrail records AWS Management  Console actions and API calls. | nist-multi-region-cloudtrail-enabled                       |
| Enable Amazon Relational Database Service  (Amazon RDS) to help monitor Amazon RDS availability. This provides detailed  visibility into the health of your Amazon RDS database instances. | nist-rds-enhanced-monitoring-enabled                       |
| To help with data back-up processes,  ensure your Amazon Relational Database Service (Amazon RDS) instances are a  part of an AWS Backup plan. AWS Backup is a fully managed backup service with  a policy-based backup solution. | nist-rds-in-backup-plan                                    |
| Ensure Amazon Relational Database Service  (Amazon RDS) instances have deletion protection enabled. | nist-rds-instance-deletion-protection-enabled              |
| Manage access to resources in the AWS  Cloud by ensuring that Amazon Relational Database Service (Amazon RDS)  instances are not public. | nist-rds-instance-public-access-check                      |
| To help with logging and monitoring  within your environment, ensure Amazon Relational Database Service (Amazon  RDS) logging is enabled. With Amazon RDS logging, you can capture events such  as connections, disconnections, queries, or tables queried. | nist-rds-logging-enabled                                   |
| Multi-AZ support in Amazon Relational  Database Service (Amazon RDS) provides enhanced availability and durability  for database instances. | nist-rds-multi-az-support                                  |
| Ensure that encryption is enabled for  your Amazon Relational Database Service (Amazon RDS) snapshots. Because  sensitive data can exist at rest, enable encryption at rest to help protect  that data. | nist-rds-snapshot-encrypted                                |
| Manage access to resources in the AWS  Cloud by ensuring that Amazon Relational Database Service (Amazon RDS)  instances are not public. | nist-rds-snapshots-public-prohibited                       |
| To help protect data at rest, ensure that  encryption is enabled for your Amazon Relational Database Service (Amazon  RDS) instances. Because sensitive data can exist at rest in Amazon RDS  instances, enable encryption at rest to help protect that data. | nist-rds-storage-encrypted                                 |
| To protect data at rest, ensure that  encryption is enabled for your Amazon Redshift clusters. You must also ensure  that required configurations are deployed on Amazon Redshift clusters. | nist-redshift-cluster-configuration-check                  |
| Manage access to resources in the AWS  Cloud by ensuring that Amazon Redshift clusters are not public. Amazon  Redshift clusters can contain sensitive information and principles and access  control is required for such accounts. | nist-redshift-cluster-public-access-check                  |
| Ensure that your Amazon Redshift clusters  require TLS/SSL encryption to connect to SQL clients. Because sensitive data  can exist, enable encryption in transit to help protect that data. | nist-redshift-require-tls-ssl                              |
| Manage access to resources in the AWS  Cloud by ensuring common ports are restricted on Amazon Elastic Compute Cloud  (Amazon EC2) security groups. | nist-restricted-common-ports                               |
| Amazon Elastic Compute Cloud (Amazon EC2)  Security Groups can help manage network access by providing stateful  filtering of ingress and egress network traffic to AWS resources. | nist-restricted-ssh                                        |
| Manage access to resources in the AWS  Cloud by ensuring hardware MFA is enabled for the root user. The root user is  the most privileged user in an AWS account. The MFA adds an extra layer of  protection for a user name and password. | nist-root-account-hardware-mfa-enabled                     |
| Manage access to resources in the AWS  Cloud by ensuring MFA is enabled for the root user. The root user is the most  privileged user in an AWS account. | nist-root-account-mfa-enabled                              |
| Manage access to resources in the AWS  Cloud by ensuring that Amazon Simple Storage Service (Amazon S3) buckets  cannot be publicly accessed. | nist-s3-account-level-public-access-blocks                 |
| Ensure that your Amazon Simple Storage  Service (Amazon S3) bucket has lock enabled, by default. Because sensitive  data can exist at rest in S3 buckets, enforce object locks at rest to help  protect that data. | nist-s3-bucket-default-lock-enabled                        |
| Amazon Simple Storage Service (Amazon S3)  server access logging provides a method to monitor the network for potential  cybersecurity events. | nist-s3-bucket-logging-enabled                             |
| Manage access to the AWS Cloud by  enabling s3_ bucket_policy_grantee_check. | nist-s3-bucket-policy-grantee-check                        |
| Manage access to resources in the AWS  Cloud by only allowing authorized users, processes, and devices access to  Amazon Simple Storage Service (Amazon S3) buckets. The management of access  should be consistent with the classification of the data. | nist-s3-bucket-public-read-prohibited                      |
| Manage access to resources in the AWS  Cloud by only allowing authorized users, processes, and devices access to  Amazon Simple Storage Service (Amazon S3) buckets. The management of access  should be consistent with the classification of the data. | nist-s3-bucket-public-write-prohibited                     |
| Amazon Simple Storage Service (Amazon S3)  Cross-Region Replication (CRR) supports maintaining adequate capacity and  availability. | nist-s3-bucket-replication-enabled                         |
| To help protect data at rest, ensure  encryption is enabled for your Amazon Simple Storage Service (Amazon S3)  buckets. Because sensitive data can exist at rest in Amazon S3 buckets,  enable encryption to help protect that data. | nist-s3-bucket-server-side-encryption-enabled              |
| To help protect data in transit, ensure  that your Amazon Simple Storage Service (Amazon S3) buckets require requests  to use Secure Socket Layer (SSL). Because sensitive data can exist, enable  encryption in transit to help protect that data. | nist-s3-bucket-ssl-requests-only                           |
| Amazon Simple Storage Service (Amazon S3)  bucket versioning helps keep multiple variants of an object in the same  Amazon S3 bucket. | nist-s3-bucket-versioning-enabled                          |
| To help protect data at rest, ensure  encryption with AWS Key Management Service (AWS KMS) is enabled for your  SageMaker endpoint. Because sensitive data can exist at rest in SageMaker  endpoint, enable encryption at rest to help protect that data. | nist-sagemaker-endpoint-configuration-kms-key-configured   |
| To help protect data at rest, ensure  encryption with AWS Key Management Service (AWS KMS) is enabled for your  SageMaker notebook. Because sensitive data can exist at rest in SageMaker  notebook, enable encryption at rest to help protect that data. | nist-sagemaker-notebook-instance-kms-key-configured        |
| Manage access to resources in the AWS  Cloud by ensuring that Amazon SageMaker notebooks do not allow direct  internet access. By preventing direct internet access, you can keep sensitive  data from being accessed by unauthorized users. | nist-sagemaker-notebook-no-direct-internet-access          |
| This rule ensures that AWS Secrets  Manager secrets have rotated successfully according to the rotation schedule.  Rotating secrets on a regular schedule can shorten the period that a secret  is active, reducing the business impact if it is compromised. | nist-secretsmanager-scheduled-rotation-success-check       |
| AWS Security Hub helps to monitor  unauthorized personnel, connections, devices, and software. AWS Security Hub  aggregates, organizes, and prioritizes the security alerts, or findings, from  multiple AWS services. | nist-securityhub-enabled                                   |
| To help protect data at rest, ensure that  your Amazon Simple Notification Service (Amazon SNS) topics require  encryption using AWS Key Management Service (AWS KMS). | nist-sns-encrypted-kms                                     |
| Amazon Elastic Compute Cloud (Amazon EC2)  security groups can help in the management of network access by providing  stateful filtering of ingress and egress network traffic to AWS resources. | nist-vpc-default-security-group-closed                     |
| The VPC flow logs provide detailed  records for information about the IP traffic going to and from network  interfaces in your Amazon Virtual Private Cloud (Amazon VPC). | nist-vpc-flow-logs-enabled                                 |
| Manage access to resources in the AWS  Cloud by ensuring common ports are restricted on Amazon Elastic Compute Cloud  (Amazon EC2) Security Groups. | nist-vpc-sg-open-only-to-authorized-ports                  |
| Redundant Site-to-Site VPN tunnels can be  implemented to achieve resilience requirements. It uses two tunnels to help  ensure connectivity in case one of the Site-to-Site VPN connections becomes  unavailable. | nist-vpc-vpn-2-tunnels-up                                  |
| To help with logging and monitoring  within your environment, enable AWS WAF (V2) logging on regional and global  web ACLs. AWS WAF logging provides detailed information about the traffic  that is analyzed by your web ACL. | nist-wafv2-logging-enabled  

### NIST Control Mapping

| NIST  Control | Family | NIST Control Parent | AWS Config Managed Key                                  |
| ------------- | ------ | ------------------- | ------------------------------------------------------- |
| AC-2(1)       | AC     | AC-2                | access-keys-rotated                                     |
| AC-2(j)       | AC     | AC-2                | access-keys-rotated                                     |
| AC-17(2)      | AC     | AC-17               | acm-certificate-expiration-check                        |
| AC-4          | AC     | AC-4                | acm-certificate-expiration-check                        |
| SC-12         | SC     | SC-12               | acm-certificate-expiration-check                        |
| AC-17(2)      | AC     | AC-17               | alb-http-drop-invalid-header-enabled                    |
| SC-23         | SC     | SC-23               | alb-http-drop-invalid-header-enabled                    |
| SC-7          | SC     | SC-7                | alb-http-drop-invalid-header-enabled                    |
| SC-8          | SC     | SC-8                | alb-http-drop-invalid-header-enabled                    |
| SC-8(1)       | SC     | SC-8                | alb-http-drop-invalid-header-enabled                    |
| AC-17(2)      | AC     | AC-17               | alb-http-to-https-redirection-check                     |
| SC-13         | SC     | SC-13               | alb-http-to-https-redirection-check                     |
| SC-23         | SC     | SC-23               | alb-http-to-https-redirection-check                     |
| SC-7          | SC     | SC-7                | alb-http-to-https-redirection-check                     |
| SC-8          | SC     | SC-8                | alb-http-to-https-redirection-check                     |
| SC-8(1)       | SC     | SC-8                | alb-http-to-https-redirection-check                     |
| SC-7          | SC     | SC-7                | alb-waf-enabled                                         |
| SI-4(a)       | SI     | SI-4                | alb-waf-enabled                                         |
| SI-4(b)       | SI     | SI-4                | alb-waf-enabled                                         |
| SI-4(c)       | SI     | SI-4                | alb-waf-enabled                                         |
| SC-13         | SC     | SC-13               | api-gw-cache-enabled-and-encrypted                      |
| SC-28         | SC     | SC-28               | api-gw-cache-enabled-and-encrypted                      |
| AU-12(a)      | AU     | AU-12               | api-gw-execution-logging-enabled                        |
| AU-12(c)      | AU     | AU-12               | api-gw-execution-logging-enabled                        |
| AU-2(a)       | AU     | AU-2                | api-gw-execution-logging-enabled                        |
| AU-2(d)       | AU     | AU-2                | api-gw-execution-logging-enabled                        |
| AU-3          | AU     | AU-3                | api-gw-execution-logging-enabled                        |
| SC-5          | SC     | SC-5                | autoscaling-group-elb-healthcheck-required              |
| AC-2(4)       | AC     | AC-2                | cloud-trail-cloud-watch-logs-enabled                    |
| AC-2(g)       | AC     | AC-2                | cloud-trail-cloud-watch-logs-enabled                    |
| AU-12(a)      | AU     | AU-12               | cloud-trail-cloud-watch-logs-enabled                    |
| AU-12(c)      | AU     | AU-12               | cloud-trail-cloud-watch-logs-enabled                    |
| AU-2(a)       | AU     | AU-2                | cloud-trail-cloud-watch-logs-enabled                    |
| AU-2(d)       | AU     | AU-2                | cloud-trail-cloud-watch-logs-enabled                    |
| AU-3          | AU     | AU-3                | cloud-trail-cloud-watch-logs-enabled                    |
| AU-6(1)       | AU     | AU-6                | cloud-trail-cloud-watch-logs-enabled                    |
| AU-6(3)       | AU     | AU-6                | cloud-trail-cloud-watch-logs-enabled                    |
| AU-7(1)       | AU     | AU-7                | cloud-trail-cloud-watch-logs-enabled                    |
| CA-7(a)       | CA     | CA-7                | cloud-trail-cloud-watch-logs-enabled                    |
| CA-7(b)       | CA     | CA-7                | cloud-trail-cloud-watch-logs-enabled                    |
| SI-4(2)       | SI     | SI-4                | cloud-trail-cloud-watch-logs-enabled                    |
| SI-4(4)       | SI     | SI-4                | cloud-trail-cloud-watch-logs-enabled                    |
| SI-4(5)       | SI     | SI-4                | cloud-trail-cloud-watch-logs-enabled                    |
| SI-4(a)       | SI     | SI-4                | cloud-trail-cloud-watch-logs-enabled                    |
| SI-4(b)       | SI     | SI-4                | cloud-trail-cloud-watch-logs-enabled                    |
| SI-4(c)       | SI     | SI-4                | cloud-trail-cloud-watch-logs-enabled                    |
| AU-9          | AU     | AU-9                | cloud-trail-encryption-enabled                          |
| SC-13         | SC     | SC-13               | cloud-trail-encryption-enabled                          |
| SC-28         | SC     | SC-28               | cloud-trail-encryption-enabled                          |
| SI-7          | SI     | SI-7                | cloud-trail-log-file-validation-enabled                 |
| SI-7(1)       | SI     | SI-7                | cloud-trail-log-file-validation-enabled                 |
| AC-2(4)       | AC     | AC-2                | cloudtrail-enabled                                      |
| AC-2(g)       | AC     | AC-2                | cloudtrail-enabled                                      |
| AU-12(a)      | AU     | AU-12               | cloudtrail-enabled                                      |
| AU-12(c)      | AU     | AU-12               | cloudtrail-enabled                                      |
| AU-2(a)       | AU     | AU-2                | cloudtrail-enabled                                      |
| AU-2(d)       | AU     | AU-2                | cloudtrail-enabled                                      |
| AU-3          | AU     | AU-3                | cloudtrail-enabled                                      |
| AC-2(g)       | AC     | AC-2                | cloudtrail-s3-dataevents-enabled                        |
| AU-12(a)      | AU     | AU-12               | cloudtrail-s3-dataevents-enabled                        |
| AU-12(c)      | AU     | AU-12               | cloudtrail-s3-dataevents-enabled                        |
| AU-2(a)       | AU     | AU-2                | cloudtrail-s3-dataevents-enabled                        |
| AU-2(d)       | AU     | AU-2                | cloudtrail-s3-dataevents-enabled                        |
| AU-3          | AU     | AU-3                | cloudtrail-s3-dataevents-enabled                        |
| CM-2          | CM     | CM-2                | cloudtrail-security-trail-enabled                       |
| AC-2(4)       | AC     | AC-2                | cloudwatch-alarm-action-check                           |
| AU-6(1)       | AU     | AU-6                | cloudwatch-alarm-action-check                           |
| AU-6(3)       | AU     | AU-6                | cloudwatch-alarm-action-check                           |
| AU-7(1)       | AU     | AU-7                | cloudwatch-alarm-action-check                           |
| CA-7(a)       | CA     | CA-7                | cloudwatch-alarm-action-check                           |
| CA-7(b)       | CA     | CA-7                | cloudwatch-alarm-action-check                           |
| IR-4(1)       | IR     | IR-4                | cloudwatch-alarm-action-check                           |
| SI-4(2)       | SI     | SI-4                | cloudwatch-alarm-action-check                           |
| SI-4(4)       | SI     | SI-4                | cloudwatch-alarm-action-check                           |
| SI-4(5)       | SI     | SI-4                | cloudwatch-alarm-action-check                           |
| SI-4(a)       | SI     | SI-4                | cloudwatch-alarm-action-check                           |
| SI-4(b)       | SI     | SI-4                | cloudwatch-alarm-action-check                           |
| SI-4(c)       | SI     | SI-4                | cloudwatch-alarm-action-check                           |
| AU-9          | AU     | AU-9                | cloudwatch-log-group-encrypted                          |
| SC-13         | SC     | SC-13               | cloudwatch-log-group-encrypted                          |
| SC-28         | SC     | SC-28               | cloudwatch-log-group-encrypted                          |
| SC-12         | SC     | SC-12               | cmk-backing-key-rotation-enabled                        |
| AC-6          | AC     | AC-6                | codebuild-project-envvar-awscred-check                  |
| IA-5(7)       | IA     | IA-5                | codebuild-project-envvar-awscred-check                  |
| SA-3(a)       | SA     | SA-3                | codebuild-project-envvar-awscred-check                  |
| SA-3(a)       | SA     | SA-3                | codebuild-project-source-repo-url-check                 |
| AU-11         | AU     | AU-11               | cw-loggroup-retention-period-check                      |
| SI-12         | SI     | SI-12               | cw-loggroup-retention-period-check                      |
| CP-10         | CP     | CP-10               | db-instance-backup-enabled                              |
| CP-9(b)       | CP     | CP-9                | db-instance-backup-enabled                              |
| SI-12         | SI     | SI-12               | db-instance-backup-enabled                              |
| AC-21(b)      | AC     | AC-21               | dms-replication-not-public                              |
| AC-3          | AC     | AC-3                | dms-replication-not-public                              |
| AC-4          | AC     | AC-4                | dms-replication-not-public                              |
| AC-6          | AC     | AC-6                | dms-replication-not-public                              |
| SC-7          | SC     | SC-7                | dms-replication-not-public                              |
| SC-7(3)       | SC     | SC-7                | dms-replication-not-public                              |
| CP-10         | CP     | CP-10               | dynamodb-autoscaling-enabled                            |
| SC-5          | SC     | SC-5                | dynamodb-autoscaling-enabled                            |
| CP-10         | CP     | CP-10               | dynamodb-in-backup-plan                                 |
| CP-9(b)       | CP     | CP-9                | dynamodb-in-backup-plan                                 |
| SI-12         | SI     | SI-12               | dynamodb-in-backup-plan                                 |
| CP-10         | CP     | CP-10               | dynamodb-pitr-enabled                                   |
| CP-9(b)       | CP     | CP-9                | dynamodb-pitr-enabled                                   |
| SI-12         | SI     | SI-12               | dynamodb-pitr-enabled                                   |
| SC-13         | SC     | SC-13               | dynamodb-table-encrypted-kms                            |
| CP-10         | CP     | CP-10               | ebs-in-backup-plan                                      |
| CP-9(b)       | CP     | CP-9                | ebs-in-backup-plan                                      |
| SI-12         | SI     | SI-12               | ebs-in-backup-plan                                      |
| AC-21(b)      | AC     | AC-21               | ebs-snapshot-public-restorable-check                    |
| AC-3          | AC     | AC-3                | ebs-snapshot-public-restorable-check                    |
| AC-4          | AC     | AC-4                | ebs-snapshot-public-restorable-check                    |
| AC-6          | AC     | AC-6                | ebs-snapshot-public-restorable-check                    |
| SC-7          | SC     | SC-7                | ebs-snapshot-public-restorable-check                    |
| SC-7(3)       | SC     | SC-7                | ebs-snapshot-public-restorable-check                    |
| SC-28         | SC     | SC-2                | ec2-ebs-encryption-by-default                           |
| AC-6          | AC     | AC-6                | ec2-imdsv2-check                                        |
| CA-7(a)       | CA     | CA-7                | ec2-instance-detailed-monitoring-enabled                |
| CA-7(b)       | CA     | CA-7                | ec2-instance-detailed-monitoring-enabled                |
| SI-4(2)       | SI     | SI-4                | ec2-instance-detailed-monitoring-enabled                |
| SI-4(a)       | SI     | SI-4                | ec2-instance-detailed-monitoring-enabled                |
| SI-4(b)       | SI     | SI-4                | ec2-instance-detailed-monitoring-enabled                |
| SI-4(c)       | SI     | SI-4                | ec2-instance-detailed-monitoring-enabled                |
| CM-2          | CM     | CM-2                | ec2-instance-managed-by-systems-manager                 |
| CM-7(a)       | CM     | CM-7                | ec2-instance-managed-by-systems-manager                 |
| CM-8(1)       | CM     | CM-8                | ec2-instance-managed-by-systems-manager                 |
| CM-8(3)(a)    | CM     | CM-8                | ec2-instance-managed-by-systems-manager                 |
| SA-10         | SA     | SA-10               | ec2-instance-managed-by-systems-manager                 |
| SA-3(a)       | SA     | SA-3                | ec2-instance-managed-by-systems-manager                 |
| SI-2(2)       | SI     | SI-2                | ec2-instance-managed-by-systems-manager                 |
| SI-7(1)       | SI     | SI-7                | ec2-instance-managed-by-systems-manager                 |
| AC-21(b)      | AC     | AC-21               | ec2-instance-no-public-ip                               |
| AC-4          | AC     | AC-4                | ec2-instance-no-public-ip                               |
| AC-6          | AC     | AC-6                | ec2-instance-no-public-ip                               |
| SC-7          | SC     | SC-7                | ec2-instance-no-public-ip                               |
| SC-7(3)       | SC     | SC-7                | ec2-instance-no-public-ip                               |
| AC-4          | AC     | AC-4                | ec2-instances-in-vpc                                    |
| SC-7          | SC     | SC-7                | ec2-instances-in-vpc                                    |
| SC-7(3)       | SC     | SC-7                | ec2-instances-in-vpc                                    |
| CM-2          | CM     | CM-2                | ec2-managedinstance-association-compliance-status-check |
| CM-7(a)       | CM     | CM-7                | ec2-managedinstance-association-compliance-status-check |
| CM-8(3)(a)    | CM     | CM-8                | ec2-managedinstance-association-compliance-status-check |
| SI-2(2)       | SI     | SI-2                | ec2-managedinstance-association-compliance-status-check |
| CM-8(3)(a)    | CM     | CM-8                | ec2-managedinstance-patch-compliance-status-check       |
| SI-2(2)       | SI     | SI-2                | ec2-managedinstance-patch-compliance-status-check       |
| SI-7(1)       | SI     | SI-7                | ec2-managedinstance-patch-compliance-status-check       |
| CM-2          | CM     | CM-2                | ec2-stopped-instance                                    |
| CM-2          | CM     | CM-2                | ec2-volume-inuse-check                                  |
| SC-4          | SC     | SC-4                | ec2-volume-inuse-check                                  |
| SC-13         | SC     | SC-13               | efs-encrypted-check                                     |
| SC-28         | SC     | SC-28               | efs-encrypted-check                                     |
| CP-10         | CP     | CP-10               | efs-in-backup-plan                                      |
| CP-9(b)       | CP     | CP-9                | efs-in-backup-plan                                      |
| SI-12         | SI     | SI-12               | efs-in-backup-plan                                      |
| CP-10         | CP     | CP-10               | elasticache-redis-cluster-automatic-backup-check        |
| CP-9(b)       | CP     | CP-9                | elasticache-redis-cluster-automatic-backup-check        |
| SI-12         | SI     | SI-12               | elasticache-redis-cluster-automatic-backup-check        |
| SC-13         | SC     | SC-13               | elasticsearch-encrypted-at-rest                         |
| SC-28         | SC     | SC-28               | elasticsearch-encrypted-at-rest                         |
| AC-4          | AC     | AC-4                | elasticsearch-in-vpc-only                               |
| SC-7          | SC     | SC-7                | elasticsearch-in-vpc-only                               |
| SC-7(3)       | SC     | SC-7                | elasticsearch-in-vpc-only                               |
| SC-7          | SC     | SC-7                | elasticsearch-node-to-node-encryption-check             |
| SC-8          | SC     | SC-8                | elasticsearch-node-to-node-encryption-check             |
| SC-8(1)       | SC     | SC-8                | elasticsearch-node-to-node-encryption-check             |
| AC-17(2)      | AC     | AC-17               | elb-acm-certificate-required                            |
| SC-13         | SC     | SC-13               | elb-acm-certificate-required                            |
| SC-7          | SC     | SC-7                | elb-acm-certificate-required                            |
| SC-8          | SC     | SC-8                | elb-acm-certificate-required                            |
| SC-8(1)       | SC     | SC-8                | elb-acm-certificate-required                            |
| CP-10         | CP     | CP-10               | elb-cross-zone-load-balancing-enabled                   |
| SC-5          | SC     | SC-5                | elb-cross-zone-load-balancing-enabled                   |
| CM-2          | CM     | CM-2                | elb-deletion-protection-enabled                         |
| CP-10         | CP     | CP-10               | elb-deletion-protection-enabled                         |
| AU-12(a)      | AU     | AU-12               | elb-logging-enabled                                     |
| AU-12(c)      | AU     | AU-12               | elb-logging-enabled                                     |
| AU-2(a)       | AU     | AU-2                | elb-logging-enabled                                     |
| AU-2(d)       | AU     | AU-2                | elb-logging-enabled                                     |
| AU-3          | AU     | AU-3                | elb-logging-enabled                                     |
| AC-17(2)      | AC     | AC-17               | elb-tls-https-listeners-only                            |
| SC-23         | SC     | SC-23               | elb-tls-https-listeners-only                            |
| SC-7          | SC     | SC-7                | elb-tls-https-listeners-only                            |
| SC-8          | SC     | SC-8                | elb-tls-https-listeners-only                            |
| SC-8(1)       | SC     | SC-8                | elb-tls-https-listeners-only                            |
| AC-2(j)       | AC     | AC-2                | emr-kerberos-enabled                                    |
| AC-3          | AC     | AC-3                | emr-kerberos-enabled                                    |
| AC-5c         | AC     | AC-5                | emr-kerberos-enabled                                    |
| AC-6          | AC     | AC-6                | emr-kerberos-enabled                                    |
| AC-21(b)      | AC     | AC-21               | emr-master-no-public-ip                                 |
| AC-4          | AC     | AC-4                | emr-master-no-public-ip                                 |
| SC-7          | SC     | SC-7                | emr-master-no-public-ip                                 |
| SC-7(3)       | SC     | SC-7                | emr-master-no-public-ip                                 |
| SC-13         | SC     | SC-13               | encrypted-volumes                                       |
| SC-28         | SC     | SC-28               | encrypted-volumes                                       |
| AC-17(1)      | AC     | AC-17               | guardduty-enabled-centralized                           |
| AC-2(1)       | AC     | AC-2                | guardduty-enabled-centralized                           |
| AC-2(12)(a)   | AC     | AC-2                | guardduty-enabled-centralized                           |
| AC-2(4)       | AC     | AC-2                | guardduty-enabled-centralized                           |
| AC-2(g)       | AC     | AC-2                | guardduty-enabled-centralized                           |
| AU-6(1)       | AU     | AU-6                | guardduty-enabled-centralized                           |
| AU-6(3)       | AU     | AU-6                | guardduty-enabled-centralized                           |
| CA-7(a)       | CA     | CA-7                | guardduty-enabled-centralized                           |
| CA-7(b)       | CA     | CA-7                | guardduty-enabled-centralized                           |
| RA-5          | RA     | RA-5                | guardduty-enabled-centralized                           |
| SA-10         | SA     | SA-10               | guardduty-enabled-centralized                           |
| SI-4(1)       | SI     | SI-4                | guardduty-enabled-centralized                           |
| SI-4(16)      | SI     | SI-4                | guardduty-enabled-centralized                           |
| SI-4(2)       | SI     | SI-4                | guardduty-enabled-centralized                           |
| SI-4(4)       | SI     | SI-4                | guardduty-enabled-centralized                           |
| SI-4(5)       | SI     | SI-4                | guardduty-enabled-centralized                           |
| SI-4(a)       | SI     | SI-4                | guardduty-enabled-centralized                           |
| SI-4(b)       | SI     | SI-4                | guardduty-enabled-centralized                           |
| SI-4(c)       | SI     | SI-4                | guardduty-enabled-centralized                           |
| IR-4(1)       | IR     | IR-4                | guardduty-non-archived-findings                         |
| IR-6(1)       | IR     | IR-6                | guardduty-non-archived-findings                         |
| IR-7(1)       | IR     | IR-7                | guardduty-non-archived-findings                         |
| RA-5          | RA     | RA-5                | guardduty-non-archived-findings                         |
| SA-10         | SA     | SA-10               | guardduty-non-archived-findings                         |
| SI-4(a)       | SI     | SI-4                | guardduty-non-archived-findings                         |
| SI-4(b)       | SI     | SI-4                | guardduty-non-archived-findings                         |
| SI-4(c)       | SI     | SI-4                | guardduty-non-archived-findings                         |
| AC-2(j)       | AC     | AC-2                | iam-group-has-users-check                               |
| AC-3          | AC     | AC-3                | iam-group-has-users-check                               |
| AC-5c         | AC     | AC-5                | iam-group-has-users-check                               |
| AC-6          | AC     | AC-6                | iam-group-has-users-check                               |
| SC-2          | SC     | SC-2                | iam-group-has-users-check                               |
| AC-6          | AC     | AC-6                | iam-no-inline-policy-check                              |
| AC-2(1)       | AC     | AC-2                | iam-password-policy                                     |
| AC-2(f)       | AC     | AC-2                | iam-password-policy                                     |
| AC-2(j)       | AC     | AC-2                | iam-password-policy                                     |
| IA-2          | IA     | IA-2                | iam-password-policy                                     |
| IA-5(1)(a)    | IA     | IA-5                | iam-password-policy                                     |
| IA-5(1)(d)    | IA     | IA-5                | iam-password-policy                                     |
| IA-5(1)(e)    | IA     | IA-5                | iam-password-policy                                     |
| IA-5(4)       | IA     | IA-5                | iam-password-policy                                     |
| AC-2(j)       | AC     | AC-2                | iam-policy-no-statements-with-admin-access              |
| AC-3          | AC     | AC-3                | iam-policy-no-statements-with-admin-access              |
| AC-5c         | AC     | AC-5                | iam-policy-no-statements-with-admin-access              |
| AC-6          | AC     | AC-6                | iam-policy-no-statements-with-admin-access              |
| SC-2          | SC     | SC-2                | iam-policy-no-statements-with-admin-access              |
| AC-2(f)       | AC     | AC-2                | iam-root-access-key-check                               |
| AC-2(j)       | AC     | AC-2                | iam-root-access-key-check                               |
| AC-3          | AC     | AC-3                | iam-root-access-key-check                               |
| AC-6          | AC     | AC-6                | iam-root-access-key-check                               |
| AC-6(10)      | AC     | AC-6                | iam-root-access-key-check                               |
| AC-2(1)       | AC     | AC-2                | iam-user-group-membership-check                         |
| AC-2(j)       | AC     | AC-2                | iam-user-group-membership-check                         |
| AC-3          | AC     | AC-3                | iam-user-group-membership-check                         |
| AC-6          | AC     | AC-6                | iam-user-group-membership-check                         |
| IA-2(1)       | IA     | IA-2                | iam-user-mfa-enabled                                    |
| IA-2(11)      | IA     | IA-2                | iam-user-mfa-enabled                                    |
| IA-2(2)       | IA     | IA-2                | iam-user-mfa-enabled                                    |
| AC-2(j)       | AC     | AC-2                | iam-user-no-policies-check                              |
| AC-3          | AC     | AC-3                | iam-user-no-policies-check                              |
| AC-5c         | AC     | AC-5                | iam-user-no-policies-check                              |
| AC-6          | AC     | AC-6                | iam-user-no-policies-check                              |
| AC-2(1)       | AC     | AC-2                | iam-user-unused-credentials-check                       |
| AC-2(3)       | AC     | AC-2                | iam-user-unused-credentials-check                       |
| AC-2(f)       | AC     | AC-2                | iam-user-unused-credentials-check                       |
| AC-3          | AC     | AC-3                | iam-user-unused-credentials-check                       |
| AC-6          | AC     | AC-6                | iam-user-unused-credentials-check                       |
| AC-17(3)      | AC     | AC-17               | internet-gateway-authorized-vpc-only                    |
| AC-4          | AC     | AC-4                | internet-gateway-authorized-vpc-only                    |
| SC-7          | SC     | SC-7                | internet-gateway-authorized-vpc-only                    |
| SC-7(3)       | SC     | SC-7                | internet-gateway-authorized-vpc-only                    |
| SC-12         | SC     | SC-12               | kms-cmk-not-scheduled-for-deletion                      |
| SC-28         | SC     | SC-28               | kms-cmk-not-scheduled-for-deletion                      |
| AC-21(b)      | AC     | AC-21               | lambda-function-public-access-prohibited                |
| AC-3          | AC     | AC-3                | lambda-function-public-access-prohibited                |
| AC-4          | AC     | AC-4                | lambda-function-public-access-prohibited                |
| AC-6          | AC     | AC-6                | lambda-function-public-access-prohibited                |
| SC-7          | SC     | SC-7                | lambda-function-public-access-prohibited                |
| SC-7(3)       | SC     | SC-7                | lambda-function-public-access-prohibited                |
| AC-4          | AC     | AC-4                | lambda-inside-vpc                                       |
| SC-7          | SC     | SC-7                | lambda-inside-vpc                                       |
| SC-7(3)       | SC     | SC-7                | lambda-inside-vpc                                       |
| IA-2(1)       | IA     | IA-2                | mfa-enabled-for-iam-console-access                      |
| IA-2(11)      | IA     | IA-2                | mfa-enabled-for-iam-console-access                      |
| IA-2(2)       | IA     | IA-2                | mfa-enabled-for-iam-console-access                      |
| AC-2(4)       | AC     | AC-2                | multi-region-cloudtrail-enabled                         |
| AU-12(a)      | AU     | AU-12               | multi-region-cloudtrail-enabled                         |
| AU-12(c)      | AU     | AU-12               | multi-region-cloudtrail-enabled                         |
| AU-2(a)       | AU     | AU-2                | multi-region-cloudtrail-enabled                         |
| AU-2(d)       | AU     | AU-2                | multi-region-cloudtrail-enabled                         |
| AU-3          | AU     | AU-3                | multi-region-cloudtrail-enabled                         |
| CA-7(a)       | CA     | CA-7                | rds-enhanced-monitoring-enabled                         |
| CA-7(b)       | CA     | CA-7                | rds-enhanced-monitoring-enabled                         |
| CP-10         | CP     | CP-10               | rds-in-backup-plan                                      |
| CP-9(b)       | CP     | CP-9                | rds-in-backup-plan                                      |
| SI-12         | SI     | SI-12               | rds-in-backup-plan                                      |
| SC-5          | SC     | SC-5                | rds-instance-deletion-protection-enabled                |
| AC-21(b)      | AC     | AC-21               | rds-instance-public-access-check                        |
| AC-4          | AC     | AC-4                | rds-instance-public-access-check                        |
| AC-6          | AC     | AC-6                | rds-instance-public-access-check                        |
| SC-7          | SC     | SC-7                | rds-instance-public-access-check                        |
| SC-7(3)       | SC     | SC-7                | rds-instance-public-access-check                        |
| AC-2(4)       | AC     | AC-2                | rds-logging-enabled                                     |
| AC-2(g)       | AC     | AC-2                | rds-logging-enabled                                     |
| AU-12(a)      | AU     | AU-12               | rds-logging-enabled                                     |
| AU-12(c)      | AU     | AU-12               | rds-logging-enabled                                     |
| AU-2(a)       | AU     | AU-2                | rds-logging-enabled                                     |
| AU-2(d)       | AU     | AU-2                | rds-logging-enabled                                     |
| AU-3          | AU     | AU-3                | rds-logging-enabled                                     |
| CP-10         | CP     | CP-10               | rds-multi-az-support                                    |
| SC-36         | SC     | SC-36               | rds-multi-az-support                                    |
| SC-5          | SC     | SC-5                | rds-multi-az-support                                    |
| SC-28         | SC     | SC-28               | rds-snapshot-encrypted                                  |
| AC-21(b)      | AC     | AC-21               | rds-snapshots-public-prohibited                         |
| AC-3          | AC     | AC-3                | rds-snapshots-public-prohibited                         |
| AC-4          | AC     | AC-4                | rds-snapshots-public-prohibited                         |
| AC-6          | AC     | AC-6                | rds-snapshots-public-prohibited                         |
| SC-7          | SC     | SC-7                | rds-snapshots-public-prohibited                         |
| SC-7(3)       | SC     | SC-7                | rds-snapshots-public-prohibited                         |
| SC-13         | SC     | SC-13               | rds-storage-encrypted                                   |
| SC-28         | SC     | SC-28               | rds-storage-encrypted                                   |
| AC-2(4)       | AC     | AC-2                | redshift-cluster-configuration-check                    |
| AC-2(g)       | AC     | AC-2                | redshift-cluster-configuration-check                    |
| AU-12(a)      | AU     | AU-12               | redshift-cluster-configuration-check                    |
| AU-12(c)      | AU     | AU-12               | redshift-cluster-configuration-check                    |
| AU-2(a)       | AU     | AU-2                | redshift-cluster-configuration-check                    |
| AU-2(d)       | AU     | AU-2                | redshift-cluster-configuration-check                    |
| AU-3          | AU     | AU-3                | redshift-cluster-configuration-check                    |
| SC-13         | SC     | SC-13               | redshift-cluster-configuration-check                    |
| SC-28         | SC     | SC-28               | redshift-cluster-configuration-check                    |
| AC-21(b)      | AC     | AC-21               | redshift-cluster-public-access-check                    |
| AC-3          | AC     | AC-3                | redshift-cluster-public-access-check                    |
| AC-4          | AC     | AC-4                | redshift-cluster-public-access-check                    |
| AC-6          | AC     | AC-6                | redshift-cluster-public-access-check                    |
| SC-7          | SC     | SC-7                | redshift-cluster-public-access-check                    |
| SC-7(3)       | SC     | SC-7                | redshift-cluster-public-access-check                    |
| AC-17(2)      | AC     | AC-17               | redshift-require-tls-ssl                                |
| SC-13         | SC     | SC-13               | redshift-require-tls-ssl                                |
| SC-7          | SC     | SC-7                | redshift-require-tls-ssl                                |
| SC-8          | SC     | SC-8                | redshift-require-tls-ssl                                |
| SC-8(1)       | SC     | SC-8                | redshift-require-tls-ssl                                |
| AC-4          | AC     | AC-4                | restricted-common-ports                                 |
| CM-2          | CM     | CM-2                | restricted-common-ports                                 |
| SC-7          | SC     | SC-7                | restricted-common-ports                                 |
| SC-7(3)       | SC     | SC-7                | restricted-common-ports                                 |
| AC-4          | AC     | AC-4                | restricted-ssh                                          |
| SC-7          | SC     | SC-7                | restricted-ssh                                          |
| SC-7(3)       | SC     | SC-7                | restricted-ssh                                          |
| IA-2(1)       | IA     | IA-2                | root-account-hardware-mfa-enabled                       |
| IA-2(11)      | IA     | IA-2                | root-account-hardware-mfa-enabled                       |
| AC-2(j)       | AC     | AC-2                | root-account-mfa-enabled                                |
| IA-2(1)       | IA     | IA-2                | root-account-mfa-enabled                                |
| IA-2(11)      | IA     | IA-2                | root-account-mfa-enabled                                |
| AC-21(b)      | AC     | AC-2                | s3-account-level-public-access-blocks                   |
| AC-3          | AC     | AC-3                | s3-account-level-public-access-blocks                   |
| AC-4          | AC     | AC-4                | s3-account-level-public-access-blocks                   |
| AC-6          | AC     | AC-6                | s3-account-level-public-access-blocks                   |
| SC-7          | SC     | SC-7                | s3-account-level-public-access-blocks                   |
| SC-7(3)       | SC     | SC-7                | s3-account-level-public-access-blocks                   |
| SC-28         | SC     | SC-28               | s3-bucket-default-lock-enabled                          |
| AC-2(g)       | AC     | AC-2                | s3-bucket-logging-enabled                               |
| AU-12(a)      | AU     | AU-12               | s3-bucket-logging-enabled                               |
| AU-12(c)      | AU     | AU-12               | s3-bucket-logging-enabled                               |
| AU-2(a)       | AU     | AU-2                | s3-bucket-logging-enabled                               |
| AU-2(d)       | AU     | AU-2                | s3-bucket-logging-enabled                               |
| AU-3          | AU     | AU-3                | s3-bucket-logging-enabled                               |
| AC-3          | AC     | AC-3                | s3-bucket-policy-grantee-check                          |
| AC-6          | AC     | AC-6                | s3-bucket-policy-grantee-check                          |
| SC-7          | SC     | SC-7                | s3-bucket-policy-grantee-check                          |
| SC-7(3)       | SC     | SC-7                | s3-bucket-policy-grantee-check                          |
| AC-21(b)      | AC     | AC-21               | s3-bucket-public-read-prohibited                        |
| AC-3          | AC     | AC-3                | s3-bucket-public-read-prohibited                        |
| AC-4          | AC     | AC-4                | s3-bucket-public-read-prohibited                        |
| AC-6          | AC     | AC-6                | s3-bucket-public-read-prohibited                        |
| SC-7          | SC     | SC-7                | s3-bucket-public-read-prohibited                        |
| SC-7(3)       | SC     | SC-7                | s3-bucket-public-read-prohibited                        |
| AC-21(b)      | AC     | AC-21               | s3-bucket-public-write-prohibited                       |
| AC-3          | AC     | AC-3                | s3-bucket-public-write-prohibited                       |
| AC-4          | AC     | AC-4                | s3-bucket-public-write-prohibited                       |
| AC-6          | AC     | AC-6                | s3-bucket-public-write-prohibited                       |
| SC-7          | SC     | SC-7                | s3-bucket-public-write-prohibited                       |
| SC-7(3)       | SC     | SC-7                | s3-bucket-public-write-prohibited                       |
| AU-9(2)       | AU     | AU-9                | s3-bucket-replication-enabled                           |
| CP-10         | CP     | CP-10               | s3-bucket-replication-enabled                           |
| CP-9(b)       | CP     | CP-9                | s3-bucket-replication-enabled                           |
| SC-36         | SC     | SC-36               | s3-bucket-replication-enabled                           |
| SC-5          | SC     | SC-5                | s3-bucket-replication-enabled                           |
| SC-13         | SC     | SC-13               | s3-bucket-server-side-encryption-enabled                |
| SC-28         | SC     | SC-28               | s3-bucket-server-side-encryption-enabled                |
| AC-17(2)      | AC     | AC-17               | s3-bucket-ssl-requests-only                             |
| SC-13         | SC     | SC-13               | s3-bucket-ssl-requests-only                             |
| SC-7          | SC     | SC-7                | s3-bucket-ssl-requests-only                             |
| SC-8          | SC     | SC-8                | s3-bucket-ssl-requests-only                             |
| SC-8(1)       | SC     | SC-8                | s3-bucket-ssl-requests-only                             |
| CP-10         | CP     | CP-10               | s3-bucket-versioning-enabled                            |
| SI-12         | SI     | SI-12               | s3-bucket-versioning-enabled                            |
| SC-13         | SC     | SC-13               | sagemaker-endpoint-configuration-kms-key-configured     |
| SC-28         | SC     | SC-28               | sagemaker-endpoint-configuration-kms-key-configured     |
| SC-13         | SC     | SC-13               | sagemaker-notebook-instance-kms-key-configured          |
| SC-28         | SC     | SC-28               | sagemaker-notebook-instance-kms-key-configured          |
| AC-21(b)      | AC     | AC-21               | sagemaker-notebook-no-direct-internet-access            |
| AC-3          | AC     | AC-3                | sagemaker-notebook-no-direct-internet-access            |
| AC-4          | AC     | AC-4                | sagemaker-notebook-no-direct-internet-access            |
| AC-6          | AC     | AC-6                | sagemaker-notebook-no-direct-internet-access            |
| SC-7          | SC     | SC-7                | sagemaker-notebook-no-direct-internet-access            |
| SC-7(3)       | SC     | SC-7                | sagemaker-notebook-no-direct-internet-access            |
| AC-2(1)       | AC     | AC-2                | secretsmanager-scheduled-rotation-success-check         |
| AC-2(j)       | AC     | AC-2                | secretsmanager-scheduled-rotation-success-check         |
| AC-17(1)      | AC     | AC-17               | securityhub-enabled                                     |
| AC-2(1)       | AC     | AC-2                | securityhub-enabled                                     |
| AC-2(12)(a)   | AC     | AC-2                | securityhub-enabled                                     |
| AC-2(4)       | AC     | AC-2                | securityhub-enabled                                     |
| AC-2(g)       | AC     | AC-2                | securityhub-enabled                                     |
| AU-6(1)       | AU     | AU-6                | securityhub-enabled                                     |
| AU-6(3)       | AU     | AU-6                | securityhub-enabled                                     |
| CA-7(a)       | CA     | CA-7                | securityhub-enabled                                     |
| CA-7(b)       | CA     | CA-7                | securityhub-enabled                                     |
| SA-10         | SA     | SA-10               | securityhub-enabled                                     |
| SI-4(16)      | SI     | SI-4                | securityhub-enabled                                     |
| SI-4(2)       | SI     | SI-4                | securityhub-enabled                                     |
| SI-4(4)       | SI     | SI-4                | securityhub-enabled                                     |
| SI-4(5)       | SI     | SI-4                | securityhub-enabled                                     |
| SI-4(a)       | SI     | SI-4                | securityhub-enabled                                     |
| SI-4(b)       | SI     | SI-4                | securityhub-enabled                                     |
| SI-4(c)       | SI     | SI-4                | securityhub-enabled                                     |
| SC-13         | SC     | SC-13               | sns-encrypted-kms                                       |
| SC-28         | SC     | SC-28               | sns-encrypted-kms                                       |
| AC-4          | AC     | AC-4                | vpc-default-security-group-closed                       |
| SC-7          | SC     | SC-7                | vpc-default-security-group-closed                       |
| SC-7(3)       | SC     | SC-7                | vpc-default-security-group-closed                       |
| AU-12(a)      | AU     | AU-12               | vpc-flow-logs-enabled                                   |
| AU-12(c)      | AU     | AU-12               | vpc-flow-logs-enabled                                   |
| AU-2(a)       | AU     | AU-2                | vpc-flow-logs-enabled                                   |
| AU-2(d)       | AU     | AU-2                | vpc-flow-logs-enabled                                   |
| AU-3          | AU     | AU-3                | vpc-flow-logs-enabled                                   |
| AC-4          | AC     | AC-4                | vpc-sg-open-only-to-authorized-ports                    |
| SC-7          | SC     | SC-7                | vpc-sg-open-only-to-authorized-ports                    |
| SC-7(3)       | SC     | SC-7                | vpc-sg-open-only-to-authorized-ports                    |
| CP-10         | CP     | CP-10               | vpc-vpn-2-tunnels-up                                    |
| AU-12(a)      | AU     | AU-12               | wafv2-logging-enabled                                   |
| AU-12(c)      | AU     | AU-12               | wafv2-logging-enabled                                   |
| AU-2(a)       | AU     | AU-2                | wafv2-logging-enabled                                   |
| AU-2(d)       | AU     | AU-2                | wafv2-logging-enabled                                   |
| AU-3          | AU     | AU-3                | wafv2-logging-enabled                                   |
| SC-7          | SC     | SC-7                | wafv2-logging-enabled                                   |
| SI-4(a)       | SI     | SI-4                | wafv2-logging-enabled                                   |
| SI-4(b)       | SI     | SI-4                | wafv2-logging-enabled                                   |
| SI-4(c)       | SI     | SI-4                | wafv2-logging-enabled                                   |


## References

[SecurityHub Official Documentatiopn](https://docs.aws.amazon.com/securityhub/index.html)
[SecurityHub 3rd Party Integrations](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-partner-providers.html)
[Forked NIST rules at Github](https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Operational-Best-Practices-for-NIST-CSF.yaml)
