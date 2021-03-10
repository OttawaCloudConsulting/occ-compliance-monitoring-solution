import boto3
import pprint
import json
from pprint import pprint
import inspect

organizations = boto3.client('organizations')
s3 = boto3.client('s3')
ec2 = boto3.client('ec2')

def org_account_list():
  account_id_list = []
  response = organizations.list_accounts()
  for account in response["Accounts"]:
    account_id_list.append(account["Id"])
  return account_id_list

def my_test():
  response2 = ec2.describe_availability_zones()
  for i in range(len(response2["AvailabilityZones"])):
    pprint(response2["AvailabilityZones"][i]["ZoneId"])

def my_test2():
  return(str(len(ec2.describe_availability_zones()["AvailabilityZones"])))

def org_account_by_name():
  response = organizations.list_accounts()
  return response["Accounts"]

def org_accountid_named_security():
  paginator = organizations.get_paginator('list_accounts')
  response_iterators = paginator.paginate()
  filtered_iterator = response_iterators.search("Accounts[?Name == `security`][]")
  account_id = None
  for filtered_response in filtered_iterator:
      account_id = filtered_response['Id']
  return account_id

def s3_paginated():
  myarray = []
  paginator = s3.get_paginator('list_objects')
  response_iterator = paginator.paginate(Bucket='aws-landingzone-landingzonepipelineartifacts3buck-5r5qoeesezzh')
  filtered_iterator = response_iterator.search("Contents[?Size > `100`][]")
  for key_data in response_iterator:
    content = (key_data["Contents"])
    for c in content:
      myarray.append(c["Key"])
  return myarray

def org_service_access_verifyconfigservice():
  paginator = organizations.get_paginator('list_aws_service_access_for_organization')
  response_iterators = paginator.paginate()
  filtered_iterator = response_iterators.search("EnabledServicePrincipals[?ServicePrincipal == `config.amazonaws.com`][]")
  myarray = None
  for filtered_response in filtered_iterator:
    # pprint(filtered_response)
    myarray = filtered_response
  if not len(myarray):
    print("Config Service not present - Failing...")
    exit(1)
    # response = organizations.enable_aws_service_access(ServicePrincipal='config.amazonaws.com')
    # Configuration surpressed as best practice is to configure via service.
  else:
    print("Config Service already enabled")
    print("Contents: {}".format(myarray))
  return myarray

def verify_delegated_administrator:

pprint(org_service_access_verifyconfigservice())