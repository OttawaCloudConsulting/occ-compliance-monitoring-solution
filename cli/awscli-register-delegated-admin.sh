#!/bin/bash

SERVICE=config.amazonaws.com
AWSACCOUNT=security
OPENTICK='"`'
CLOSETICK='`"'

# Verify that config service exists 
function verify-config-service () {
  local VARTICK=$(echo $OPENTICK$1$CLOSETICK | sed 's/"//g')
  local QUERY="EnabledServicePrincipals[?ServicePrincipal==$VARTICK].ServicePrincipal"
  local CONFIGSERVICE=$(aws organizations list-aws-service-access-for-organization \
    --query $QUERY \
    --output text)
  if [ "$CONFIGSERVICE" == "$1" ]; then
    echo "Config Service already enabled"
  else
    aws organizations enable-aws-service-access \
      --service-principal $1
  fi
}

function register-account-as-delegated-administrator () {
  aws organizations register-delegated-administrator \
    --service-principal $1 \
    --account-id $2
}

function find-aws-accountid-by-name () {
  local VARTICK=$(echo $OPENTICK$1$CLOSETICK | sed 's/"//g')
  local TRUETICK=$(echo '`"true"`'| sed 's/"//g')
  local QUERY="Accounts[?contains(Name, $VARTICK) == $TRUETICK].Id"
  aws organizations list-accounts \
    --query "$QUERY" \
    --output text
}

function verify-delegated-administrator () {
  local DELADMINID=$(aws organizations list-delegated-administrators \
    --service-principal $1 \
    --query 'DelegatedAdministrators[].Id' \
    --output text)
  if [ "$DELADMINID" == $(find-aws-accountid-by-name $AWSACCOUNT) ]; then
    echo "Organizational Delegated Admin already configured"
  else
    echo "Configuring Delegated Admin to $(find-aws-accountid-by-name $AWSACCOUNT) AWS Account"
    register-account-as-delegated-administrator $SERVICE $ACCOUNTID
  fi
}

# Execution

# 1 - Check to enable service access
verify-config-service $SERVICE 

# 2 - Check if Delegated Administrator Exists
verify-delegated-administrator $SERVICE 
