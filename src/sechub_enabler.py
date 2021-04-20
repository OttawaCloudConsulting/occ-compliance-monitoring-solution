## Python 3.7+

## Import modules
import botocore
import boto3
import logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

## Boto Aliases
securityhub = boto3.client('securityhub')
organizations = boto3.client('organizations')
sts = boto3.client('sts')
code_pipeline = boto3.client('codepipeline')

## Global Variables
security_hub_arn = None
security_account_id = None
this_account_id = boto3.client('sts').get_caller_identity().get('Account')
logger.info("Executing from %s", this_account_id)
boto3_version = boto3.__version__
IAMRemoteRole = 'AWSCloudFormationStackSetExecutionRole'

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

def verify_securityhub_enabled():
  try:
    logger.info('Calling Describe SecurityHub in local account')
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

def enable_securityhub_orgadmin(event):
  try:
    logger.info('Checking SecurityHub OrgAdmin Account')
    accounts = securityhub.list_organization_admin_accounts()["AdminAccounts"]
    if accounts:
      for account in accounts:
        accountid = account["AccountId"]
        if accountid != security_account_id:
          logger.warn('Enabled on incorrect account')
          logger.info('Setting Seucurity Account as Delegated Admin')
          logger.info('Disabling current Admin account')
          securityhub.disable_organization_admin_account(
              AdminAccountId=accountid
          )
          logger.info('Enabling Security account as delegated admin l99')
          response = securityhub.enable_organization_admin_account(
              AdminAccountId=security_account_id
          )
          enable_security_hub_auto_enable_in_remote_account()
          return response
        else:
          logger.info('Already enabled')
          response = print("Already enabled on Security Account: ",accountid)
          remote_check_if_account_present()
          # code_pipeline.put_job_success_result(jobId=event["CodePipeline.job"].get("id"))
          return response
    else:
      logger.warning('OrgAdmin not present')
      logger.info('Enabling Security account as delegated admin l117')
      response = securityhub.enable_organization_admin_account(
          AdminAccountId=security_account_id
      )
      enable_security_hub_auto_enable_in_remote_account()
      return response
  except UnboundLocalError as error:
    logger.warning('Organization configuration not found...')
    logger.info('Calling enable function...')
    response = error
    enable_security_hub_auto_enable_in_remote_account()
    return response


def enable_security_hub_auto_enable_in_remote_account():
  logger.info('Enabling Organization Admin in Security account')
  role_arn = "arn:aws:iam::"+security_account_id+":role/"+IAMRemoteRole
  logger.info("Remote execution role is %s", role_arn)
  sts_connection = boto3.client('sts')
  acct_b = sts_connection.assume_role(
      RoleArn=role_arn,
      RoleSessionName="sechub_enabler_lambda"
  )
  ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
  SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
  SESSION_TOKEN = acct_b['Credentials']['SessionToken']
  securityhubremote = boto3.client(
      'securityhub',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
  )
  logger.info("Enabling Security Hub in Security Account")
  try:
    securityhubremote.enable_security_hub(
              EnableDefaultStandards=False
          )
    logger.info("Enabling Security account as delegated admin")
    logger.info("Configuring Auto Enable for new Accounts")
    securityhubremote.update_organization_configuration(AutoEnable=True)
    remote_check_if_account_present()
  except botocore.exceptions.ClientError as error:
    if error.response['Error']['Code'] == 'ResourceConflictException':
      logger.info("Enabling Security account as delegated admin")
      logger.info("Configuring Auto Enable for new Accounts")
      securityhubremote.update_organization_configuration(AutoEnable=True)
      logger.info("Checking Member account status")
      remote_check_if_account_present()

def remote_org_account_list():
  role_arn = "arn:aws:iam::"+security_account_id+":role/"+IAMRemoteRole
  logger.info("Remote execution role is %s", role_arn)
  sts_connection = boto3.client('sts')
  acct_b = sts_connection.assume_role(
      RoleArn=role_arn,
      RoleSessionName="sechub_enabler_lambda"
  )
  ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
  SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
  SESSION_TOKEN = acct_b['Credentials']['SessionToken']
  organizationsremote = boto3.client(
      'organizations',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
  )
  logger.info("Fetching AWS Organization's Accounts list...")
  account_id_list = []
  response = organizationsremote.list_accounts()
  for account in response["Accounts"]:
    account_id_list.append(account["Id"])
  return account_id_list

def remote_check_if_account_present():
  logger.info("Starting remote_check_if_account_present function")
  role_arn = "arn:aws:iam::"+security_account_id+":role/"+IAMRemoteRole
  logger.info("Remote execution role is %s", role_arn)
  sts_connection = boto3.client('sts')
  acct_b = sts_connection.assume_role(
      RoleArn=role_arn,
      RoleSessionName="sechub_enabler_lambda"
  )
  ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
  SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
  SESSION_TOKEN = acct_b['Credentials']['SessionToken']
  securityhubremote = boto3.client(
      'securityhub',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
  )
  stsremote = boto3.client(
      'sts',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
  )
  account_id_list = remote_org_account_list()
  logger.info("Verifying Org Member Status...")
  for account in account_id_list:
    logger.info("Checking status of account %s", account)
    try:
      member_status = securityhubremote.get_members(AccountIds=[account]).get("Members")[0].get("MemberStatus")
      if member_status == 'Enabled':
        logger.info("Account %s is already enabled", account)
      else:
        logger.info("Account %s is not enabled", account)
        logger.info("Account %s is being added as Organization Member", account)
        remote_sechub_create_member(account)
    except IndexError as error:
      if account == stsremote.get_caller_identity().get('Account'):
        logger.info("Ignroing account %s as Organization Delegated Admin", account)
      else:
        logger.info("Account %s is not in index", account)
        logger.info("Account %s is being added as Organization Member", account)
        remote_sechub_create_member(account)

def remote_sechub_create_member(account):
  role_arn = "arn:aws:iam::"+security_account_id+":role/"+IAMRemoteRole
  logger.info("Remote execution role is %s", role_arn)
  sts_connection = boto3.client('sts')
  acct_b = sts_connection.assume_role(
      RoleArn=role_arn,
      RoleSessionName="sechub_enabler_lambda"
  )
  ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
  SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
  SESSION_TOKEN = acct_b['Credentials']['SessionToken']
  securityhubremote = boto3.client(
      'securityhub',
      aws_access_key_id=ACCESS_KEY,
      aws_secret_access_key=SECRET_KEY,
      aws_session_token=SESSION_TOKEN,
  )
  response = securityhubremote.create_members(
    AccountDetails=[
        {
            'AccountId': account
        },
    ]
  )
  return response

def lambda_handler(event, context):
  logger.debug("Lambda_handler Event")
  logger.debug(event)
  print("boto3 version: ",boto3_version)
  verify_securityhub_enabled()
  org_accountid_named_security()
  enable_securityhub_orgadmin(event)
  code_pipeline.put_job_success_result(jobId=event["CodePipeline.job"].get("id"))