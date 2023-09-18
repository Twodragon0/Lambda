import json
import boto3
import requests
import datetime


def returnTime(time):
    time = time.split("T")
    date = time[0]
    hour = time[1].split("Z")[0]
    ret_time = date + " " + hour
    ret_time = datetime.datetime.strptime(ret_time, '%Y-%m-%d %H:%M:%S')
    ret_time = ret_time + datetime.timedelta(hours=9)  
    
    return str(ret_time)


def lambda_handler(event, context):

    kst_time = returnTime(event["time"])
    region = event["region"]
    accountId = event["detail"]["awsAccountId"]
    rule = event["detail"]["configRuleName"]
    resource_type = event["detail"]["newEvaluationResult"]["evaluationResultIdentifier"]["evaluationResultQualifier"]["resourceType"]
    resource_id = event["detail"]["resourceId"]
    compliance = event["detail"]["newEvaluationResult"]["complianceType"]
    annotation = event.get('detail').get('newEvaluationResult').get('annotation', None)  
    if annotation is not None:
        # annotation field exists
        annotation = event['detail']['newEvaluationResult']['annotation']
    else:
        # annotation field does not exist
        annotation = " NONE " 
    
     # Set colors based on configRuleName
    if rule.startswith("s3-bucket-"):
        # Set red color for matching rule names
        color = "#FF0000"  # Red
    if rule.startswith("iam-"):
        # Set green color for configRuleName starting with "iam-"
        color = "#00FF00"  # Green
    elif rule.startswith("ec2-"):
        # Set blue color for configRuleName starting with "ec2-"
        color = "#0000FF"  # Blue
    else:
        color = "#3AA3E3"  # Default color
    
    webhook_url = "*"

    slack_data = {
        "attachments": [
            {
                "pretext": "*Config Compliance Change*",
                "title": "RawData",
                "title_link": "https://console.aws.amazon.com/config/home?region=" + region + "#/timeline/" + resource_type + "/" + resource_id + "/configuration",
                "fields": [
                    {"title": "Annotation", "value": annotation, "short": True},
                    {"title": "Compliance", "value": compliance, "short": True},
                    {"title": "Account Id", "value": accountId, "short": True},
                    {"title": "Time", "value": kst_time, "short": True},
                    {"title": "Region", "value": region, "short": True},
                    {"title": "Rule", "value": rule, "short": True},
                    {"title": "Resource Type", "value": resource_type, "short": True},
                    {"title": "Resource ID", "value": resource_id, "short": True}
                ],
                "mkdwn_in": ["pretext"],
                "color": color,  # Use the determined color here
            }
        ]
    }
    
    response = requests.post(
        webhook_url, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
    )
