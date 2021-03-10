## Python 3.7+

import json
import pprint
import boto3
organizations = boto3.client('organizations')
ec2 = boto3.client('ec2')

def org_account_list():
  account_id_list = []
  response = organizations.list_accounts()
  for account in response["Accounts"]:
    account_id_list.append(account["Id"])
  return account_id_list

def org_accountid_named_security():
    paginator = organizations.get_paginator('list_accounts')
    response_iterators = paginator.paginate()
    filtered_iterator = response_iterators.search("Accounts[?Name == `security`][]")
    account_id = None
    for filtered_response in filtered_iterator:
        account_id = filtered_response['Id']
    return account_id

def org_service_access_verifyconfigservice():
  paginator = organizations.get_paginator('list_aws_service_access_for_organization')
  response_iterators = paginator.paginate()
  filtered_iterator = response_iterators.search("EnabledServicePrincipals[?ServicePrincipal == `config.amazonaws.com`][]")
  mresponse = None
  for filtered_response in filtered_iterator:
    # pprint(filtered_response)
    mresponse = filtered_response
  if not len(mresponse):
    print("Config Service not present - Failing...")
    exit(1)
    # response = organizations.enable_aws_service_access(ServicePrincipal='config.amazonaws.com')
    # Configuration surpressed as best practice is to configure via service.
  else:
    print("Config Service already enabled")
    print("Contents: {}".format(mresponse))
  return mresponse