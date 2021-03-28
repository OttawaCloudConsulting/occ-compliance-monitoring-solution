## Python 3.7+

## Import modules
import botocore
import boto3
import pprint
import json
from pprint import pprint
import inspect
import logging
logger = logging.getLogger(__name__)

## Aliases
securityhub = boto3.client('securityhub')
organizations = boto3.client('organizations')
sts = boto3.client('sts')

## Global Variables
security_hub_arn = None
security_account_id = None
security_account_role = "AWSCloudFormationStackSetExecutionRole"
this_account_id = boto3.client('sts').get_caller_identity().get('Account')
boto3_version = boto3.__version__

## Functions
def org_account_list():
  logger.info("Fetching AWS Organization's Accounts list...")
  account_id_list = []
  response = organizations.list_accounts()
  for account in response["Accounts"]:
    account_id_list.append(account["Id"])
  return account_id_list

def org_accountid_named_security():
  logger.info("Fetching AWS Account Id for Security Account...")
  paginator = organizations.get_paginator('list_accounts')
  response_iterators = paginator.paginate()
  filtered_iterator = response_iterators.search("Accounts[?Name == `security`][]")
  global security_account_id
  for filtered_response in filtered_iterator:
      security_account_id = filtered_response['Id']
  return security_account_id

def org_service_access_verifyconfigservice():
  logger.info("Verifying Config Servce is enabled")
  paginator = organizations.get_paginator('list_aws_service_access_for_organization')
  response_iterators = paginator.paginate()
  filtered_iterator = response_iterators.search("EnabledServicePrincipals[?ServicePrincipal == `config.amazonaws.com`][]")
  mresponse = None
  for filtered_response in filtered_iterator:
    mresponse = filtered_response
  if not len(mresponse):
    print("Config Service not present - Failing...")
    exit(1)
  else:
    logger.info('Calling Describe SecurityHub')
    print("Config Service already enabled")
    logger.info("Contents: {}".format(mresponse))
  return mresponse

def verify_securityhub_enabled():
  try:
    logger.info('Calling Describe SecurityHub')
    security_hub = securityhub.describe_hub()["HubArn"]
    global security_hub_arn
    security_hub_arn = securityhub.describe_hub()["HubArn"]
    return security_hub
  except botocore.exceptions.ClientError as error:
    if error.response['Error']['Code'] == 'InvalidAccessException':
        logger.warning('SecurityHub not enabled. ')
        logger.info("Enabling Security Hub")
        securityhub.enable_security_hub(
            EnableDefaultStandards=False
        )
        security_hub = securityhub.describe_hub()["HubArn"]
        security_hub_arn = securityhub.describe_hub()["HubArn"]
        return security_hub
    else:
        raise error

def enable_securityhub_orgadmin():
  try:
    logger.info('Checking SecurityHub OrgAdmin Account')
    accounts = securityhub.list_organization_admin_accounts()["AdminAccounts"]
    for account in accounts:
      accountid = account["AccountId"]
      if accountid != security_account_id:
        logger.warn('Enabled on incorrect account')
        logger.info('Setting Seucurity Account as Delegated Admin')
        logger.info('Disabling current Admin account')
        securityhub.disable_organization_admin_account(
            AdminAccountId=accountid
        )
        logger.info('Enabling Security account as delegated admin')
        response = securityhub.enable_organization_admin_account(
            AdminAccountId=security_account_id
        )
        enable_security_hub_auto_enable_in_remote_account()
      else:
        logger.info('Already enabled')
        response = print("Already enabled on Security Account: ",accountid)
    return response
  except UnboundLocalError as error:
    logger.warning('Organization configuration not found...')
    logger.info('Enabling Organization Admin in Security account')
    response = enable_security_hub_auto_enable_in_remote_account()
    return response


def enable_security_hub_auto_enable_in_remote_account():
  logger.info('Enabling Organization Admin in Security account')
  role_arn = "arn:aws:iam::"+security_account_id+":role/"+security_account_role
  sts_connection = boto3.client('sts')
  acct_b = sts_connection.assume_role(
      RoleArn=role_arn,
      RoleSessionName="sechub_enabler_lambda"
  )

  ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
  SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
  SESSION_TOKEN = acct_b['Credentials']['SessionToken']

  client = boto3.client(
      'securityhub',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
  )
  logger.info("Enabling Security Hub in Security Account")
  client.enable_security_hub(
            EnableDefaultStandards=False
        )
  logger.info("Enabling Security account as delegated admin")
  response = securityhub.enable_organization_admin_account(
            AdminAccountId=security_account_id
        )
  logger.info("Configuring Auto Enable for new Accounts")
  client.update_organization_configuration(AutoEnable=True)

def lambda_handler(event, context):
  logger.debug("Lambda_handler Event")
  logger.debug(event)
  print("boto3 version: ",boto3_version)
  org_service_access_verifyconfigservice()
  verify_securityhub_enabled()
  org_accountid_named_security()
  enable_securityhub_orgadmin()