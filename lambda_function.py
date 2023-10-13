import boto3, os, sys, json, logging,requests, datetime

# Set the log format
logger = logging.getLogger()
for h in logger.handlers:
  logger.removeHandler(h)

h = logging.StreamHandler(sys.stdout)
FORMAT = ' [%(levelname)s]/%(asctime)s/%(name)s - %(message)s'
h.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(h)
logger.setLevel(logging.INFO)

def returnTime(eventTime):
    eventTime = eventTime.split("T")
    date = eventTime[0]
    time = eventTime[1].split("Z")[0]
    ret_time = date + " " + time
    ret_time = datetime.datetime.strptime(ret_time, '%Y-%m-%d %H:%M:%S')
    ret_time = ret_time + datetime.timedelta(hours=9)   
    
    return str(ret_time)

def consoleUrlReturn(awsRegion):
    url = "https://ap-northeast-2.console.aws.amazon.com/kms/home?region="
    consoleUrl = url + awsRegion + "#/kms/keys"
    return consoleUrl

def push_To_Slack_KMS_Change(event):
    
    try:
        #Slack
        #Define of Variable 
        apiName = event['detail']['eventName']
        apiTime = returnTime(event["detail"]["eventTime"])
        awsRegion = event["detail"]["awsRegion"]

        consoleUrl = consoleUrlReturn(awsRegion)

        if "userName" in event["detail"]["userIdentity"]:
            usrName = event["detail"]["userIdentity"]["userName"]
        else: 
            usrName = "There is no userName"

        slackPayloads = {
            "attachments" : [
                {
                    "pretext" : "*KMS Changes Monitoring*", 
                    "title" : "KMS",
                    "title_link" : consoleUrl, 
                    "fields" : [ 
                        {"title" : "Event Name", "value" : apiName, "short" : True},
                        {"title" : "Event Time", "value" : apiTime, "short" : True},
                        {"title" : "User Name", "value" : usrName, "short" : True},
                        
                    ],
                    "mkdwn_in" : ["pretext"],
                    "color" : "#3AA3E3",      
                }
            ]        
        }    
        
        #DEV Monitoring Channel Webhook  
        webhook_url = "*" 

        requests.post(
             webhook_url, data=json.dumps(slackPayloads),
             headers={'Content-Type': 'application/json'}
        )

        logger.info('SUCCESS: Security Group Change to Slack')
        return "Successly pushed to Notification to Slack"
    except KeyError as e:
        logger.error('ERROR: Unable to push to Slack: Check [1] Slack Webhook URL is invalid, [2] IAM Role Permissions{0}'.format( str(e) ) )
        logger.error('ERROR: {0}'.format( str(e) ) )


def lambda_handler(event, context):
    return push_To_Slack_KMS_Change(event)

if __name__ == '__main__':
    lambda_handler(None, None)
    
    
