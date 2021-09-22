import boto3
import os
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)
logger.setLevel(logging.INFO)

SECURITYHUB = boto3.client('securityhub')
CONFIG = boto3.client('config')
SNS = boto3.client('sns')
def get_description_of_rule(config_rule_name):
    """Gather description of config rule."""
    description = ""
    try:
        response = CONFIG.describe_config_rules(
            ConfigRuleNames=[config_rule_name]
        )
        if 'Description' in response['ConfigRules'][0]:
            description = response['ConfigRules'][0]['Description']
        else:
            description = response['ConfigRules'][0]['ConfigRuleName']
        return description
    except Exception as error:
        print("Error: ", error)
        raise
def get_compliance_and_severity(event, config_rule_name, new_status):
    """Return compliance status & severity."""
    # config_rule_name = event['detail']['configRuleName']
    rule_severity = config_rule_name.split('-')[-1]
    print("Config Rule Name:", config_rule_name)
    print("Severity:", rule_severity)
    # get_compliance_and_severity(new_status,rule_severity)
    if new_status == 'COMPLIANT':
        status = ['PASSED', 'INFORMATIONAL', 0]
    elif ((new_status == 'NON_COMPLIANT') and (rule_severity == 'low')):
        logger.info("Set severity %s...", rule_severity)
        status = ['FAILED', 'LOW', 30]
    elif ((new_status == 'NON_COMPLIANT') and (rule_severity == 'medium')):
        logger.info("Set severity %s...", rule_severity)
        status = ['FAILED', 'MEDIUM', 60]
    elif ((new_status == 'NON_COMPLIANT') and (rule_severity == 'high')):
        logger.info("Set severity %s and create alert...", rule_severity)
        status = ['FAILED', 'HIGH', 80]
        sns_alert(event, rule_severity)
    elif ((new_status == 'NON_COMPLIANT') and (rule_severity == 'critical')):
        logger.info("Set severity %s and create alert...", rule_severity)
        status = ['FAILED', 'CRITICAL', 100]
        sns_alert(event, rule_severity)
    else:
        status = ['FAILED', 'LOW', 40]
    return status
def map_config_findings_to_sh(event, old_recorded_time):
    """Create custom finding."""
    new_findings = []
    new_status = event['detail']['newEvaluationResult']['complianceType']
    config_rule_name = event['detail']['configRuleName']
    compliance_status = get_compliance_and_severity(event, config_rule_name, new_status)
    description = get_description_of_rule(config_rule_name)
    remediation_url = (f"""https://{event['detail']['awsRegion']}.console.aws.amazon.com/config/home?region={event['detail']['awsRegion']}&awsc-custsat-override=promptUser#/rules/details?configRuleName={config_rule_name}""")
    new_findings.append({
        "SchemaVersion": "2018-10-08",
        "Id": event['id'],
        "ProductArn": (f"arn:aws:securityhub:{event['detail']['awsRegion']}:"
                      f"{event['detail']['awsAccountId']}:"
                      f"product/{event['detail']['awsAccountId']}/default"),
        "GeneratorId": event['detail']['configRuleARN'],
        "AwsAccountId": event['detail']['awsAccountId'],
        "Types": [
            "Software and Configuration Checks/AWS Config Analysis"
        ],
        "CreatedAt": old_recorded_time,
        "UpdatedAt": (event['detail']
                      ['newEvaluationResult']['resultRecordedTime']),
        "Severity": {
            "Original": str(compliance_status[1]),
            "Label": compliance_status[1]
        },
        "Title": config_rule_name,
        "Description": description,
        'Remediation': {
            'Recommendation': {
                'Text': 'For directions on how to fix this issue, see the remediation action on the rule details page in AWS Config console',
                'Url': remediation_url
            }
        },
        'Resources': [
            {
                'Id': event['detail']['resourceId'],
                'Type': event['detail']['resourceType'].split(":")[-1],
                'Partition': "aws",
                'Region': event['detail']['awsRegion']
            }
        ],
        'Compliance': {'Status': compliance_status[0]}
    })
    
    if new_findings:
        try:
            response = SECURITYHUB.batch_import_findings(Findings=new_findings)
            logger.info("Response: \n %s", response)
            if response['FailedCount'] > 0:
                print(
                    "Failed to import {} findings".format(
                        response['FailedCount']))
        except Exception as error:
            print("Error: ", error)
            raise
def parse_message(event):
    """Initialize event logic."""
    details = event['detail']
    if (details['messageType'] == 'ComplianceChangeNotification' and
            "securityhub.amazonaws.com" not in details['configRuleARN']):
        if 'oldEvaluationResult' not in event['detail']:
            old_recorded_time = (event['detail']
                                ['newEvaluationResult']['resultRecordedTime'])
        else:
            old_recorded_time = (event['detail']
                                ['oldEvaluationResult']['resultRecordedTime'])
        map_config_findings_to_sh(event, old_recorded_time)
    else:
        print("Other Notification")
def sns_alert(event, rule_severity):
  var_TopicArn =  os.environ['TOPICARN']
  logger.info("SNS Notification from alert severity %s...", rule_severity)
  response = SNS.publish(
    TopicArn=var_TopicArn,
    Message=str(f"NIST Compliance Alert \nSeverity = {rule_severity} \nConfigRule={event['detail']['configRuleName']} \nAccountId = {event['detail']['awsAccountId']} \nRegion = {event['detail']['awsRegion']} \nResourceType= {event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceType']} \nResourceId= {event['detail']['newEvaluationResult']['evaluationResultIdentifier']['evaluationResultQualifier']['resourceId']} \n"),
    Subject=rule_severity
  )
  logger.info("Response: \n %s", response)
def lambda_handler(event, context):
    """Begin Lambda execution."""
    print("Event Before Parsing: ", event)
    parse_message(event)