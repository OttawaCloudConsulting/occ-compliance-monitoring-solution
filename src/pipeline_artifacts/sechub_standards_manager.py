## Python 3.7+

## Import modules
import botocore
import boto3
import os
import logging
from pprint import pprint

from botocore import validate
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
logger.setLevel(logging.INFO)

## Boto Aliases
securityhub = boto3.client('securityhub')
organizations = boto3.client('organizations')
sts = boto3.client('sts')
ec2 = boto3.client('ec2')
code_pipeline = boto3.client('codepipeline')

## Global Variables
account_id_list = []
excluded_regions = os.environ['EXCLUDED_REGIONS']   # commented out for local testing
standard_to_enable = os.environ['DESIRED_STANDARDS'] # commented out for local testing
IAMRemoteRole = os.environ['IAM_REMOTE_ROLE']
# excluded_regions = ["ca-central-1", "us-east-1"]
# standard_to_enable = 'CIS AWS Foundations Benchmark v1.2.0'
# IAMRemoteRole = 'AWSCloudFormationStackSetExecutionRole'
regions_to_enable = []
regions_to_disable = []
desired_standard = 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0'
var_remote_role_session_name = "SecHubStandardDisabler"
this_account_id = boto3.client('sts').get_caller_identity().get('Account')
logger.info("Executing from %s", this_account_id)
boto3_version = boto3.__version__


## Functions
def org_account_list():
  logger.info("Fetching AWS Organization's Accounts list...")
  response = organizations.list_accounts()
  for account in response["Accounts"]:
    account_id_list.append(account["Id"])
  return account_id_list

def get_enabled_standards():
  logger.info("Fetching enabled Standards...")
  response = securityhub.get_enabled_standards()
  return response

def disable_all_standards():
  logger.info("Disabling standards...")
  enabled_standards_list = []
  subscriptionlist = securityhub.get_enabled_standards()
  for i in subscriptionlist['StandardsSubscriptions']:
    enabled_standards_list.append(i['StandardsSubscriptionArn'])
  response = securityhub.batch_disable_standards(
      StandardsSubscriptionArns=enabled_standards_list
  )
  return enabled_standards_list

def describe_regions():
  logger.info("Fetching list of regions...")
  response = ec2.describe_regions()
  return response

def regions_enabled():
  logger.info("Building list of regions to enable standards...")
  response = describe_regions()
  data = response['Regions']
  for region in data:
      if region['RegionName'] not in excluded_regions:
          regions_to_enable.append(region['RegionName'])
  

def regions_disabled():
  logger.info("Building list of regions to disable standards...")
  response = describe_regions()
  data = response['Regions']
  for region in data:
      if region['RegionName'] in excluded_regions:
          regions_to_disable.append(region['RegionName'])
  

def enable_standards(accountid, remote_role, remote_session_name):
  pprint("Executing enable_standards function...")

  remote_role_arn = "arn:aws:iam::"+accountid+":role/"+remote_role
  sts_connection = boto3.client('sts')
  assumed_session = sts_connection.assume_role(
    RoleArn=remote_role_arn,
    RoleSessionName=remote_session_name,
  )
  ACCESS_KEY = assumed_session['Credentials']['AccessKeyId']
  SECRET_KEY = assumed_session['Credentials']['SecretAccessKey']
  SESSION_TOKEN = assumed_session['Credentials']['SessionToken']

  ## Iterate through regions and disable stanadrads
  for region in regions_to_disable:
    to_disable = []
    # logger.info("Executing in region %s of accountid %s...", region, accountid)
    remote_service_securityhub = boto3.client(
      service_name='securityhub',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
      region_name=region,
    )

    try:
      get_enabled_standards = remote_service_securityhub.get_enabled_standards()["StandardsSubscriptions"]
      pprint(get_enabled_standards)
      for c in range(len(get_enabled_standards)):
        to_disable.append(get_enabled_standards[c]["StandardsSubscriptionArn"])
      print("Checking if standards need to be disabled...")
      if not to_disable:
        logger.info("Executing in region %s of accountid %s...", region, accountid)
        print("List is empty")
      else:
        print("Disabling active standards...")
        logger.info("Executing in region %s of accountid %s...", region, accountid)
        remote_service_securityhub.batch_disable_standards(StandardsSubscriptionArns=to_disable)
    except botocore.exceptions.ClientError as error:
      if error.response['Error']['Code'] == 'InvalidAccessException':
        logger.warning('SecurityHub not enabled ')
        logger.info("Executing in region %s of accountid %s...", region, accountid)
## Iterate through regions and enable CIS stanadrads
  for region in regions_to_enable:
    to_disable2=[]
    remote_service_securityhub = boto3.client(
      service_name='securityhub',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
      region_name=region,
    )

    try:
      get_enabled_standards = remote_service_securityhub.get_enabled_standards()["StandardsSubscriptions"]
      for c in range(len(get_enabled_standards)):
        if get_enabled_standards[c]["StandardsArn"] != desired_standard:
          to_disable2.append(get_enabled_standards[c]["StandardsSubscriptionArn"])
      if not to_disable2:
        logger.info("Executing in region %s of accountid %s...", region, accountid)
        print("List is empty")
      else:
        print("Disabling active standards...")
        logger.info("Executing in region %s of accountid %s...", region, accountid)
        remote_service_securityhub.batch_disable_standards(StandardsSubscriptionArns=to_disable2)

      for v in range(len(get_enabled_standards)):
        if get_enabled_standards[v]["StandardsArn"] in standard_to_enable:
          var_validation = "CIS Present"
        else:
          var_validation = "CIS NOT Present - Enabling..."
          remote_service_securityhub.batch_enable_standards(
            StandardsSubscriptionRequests=[
              {
                'StandardsArn': desired_standard
              }
            ]
          )
    except botocore.exceptions.ClientError as error:
      if error.response['Error']['Code'] == 'InvalidAccessException':
        logger.info("Executing in region %s of accountid %s...", region, accountid)
        logger.warning('SecurityHub not enabled ')

## Execution

def lambda_handler(event, context):
  logger.debug("Lambda_handler Event")
  logger.debug(event)
  print("boto3 version: ",boto3_version)
  print("Build enabled region list")
  regions_enabled()
  print("Build disabled region list")
  regions_disabled()
  print("Build accountid list")
  org_account_list()
  for account in account_id_list:
    enable_standards(account, IAMRemoteRole, var_remote_role_session_name)
  code_pipeline.put_job_success_result(jobId=event["CodePipeline.job"].get("id"))