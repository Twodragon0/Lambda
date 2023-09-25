import boto3, os, sys, json, logging,requests, datetime
import exception_function 

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
    time = eventTime[1].split(".")[0]
    ret_time = date + " " + time
    ret_time = datetime.datetime.strptime(ret_time, '%Y-%m-%d %H:%M:%S')
    ret_time = ret_time + datetime.timedelta(hours=9)   
    
    return str(ret_time)

def returnColor(severity): 
    if severity >= 7:
        return 'danger'

    elif severity < 7 and severity >= 4:
        return 'warning'

    else: 
        return 'good'

def consoleUrlReturn(region, messageId):
    url = "https://console.aws.amazon.com/guardduty/home?region="
    consoleUrl = url + region + "#findings?search=id%3D" + messageId
    return consoleUrl


def push_To_SNS_Topic(event):
  
    event = event['detail']
    
    #exception_function 
    try:
        if exception_function.exception(event,exception_function.condition):
            print("AAAA\n")
            return

    except:
        pass    

 
    
    try:
        #Slack

        #Define of Variable 
        finding = event["type"]
        messageId = event["id"]
        region = event["region"]
        findingDescription = event["description"]
        severity = event["severity"]
        updatedAt = returnTime(event["updatedAt"])
        count = event["service"]["count"]
        consoleUrl = consoleUrlReturn(region, messageId)
        
        slackPayloads = {
            "attachments" : [
                {
                    "fallback" : "Finding - " + consoleUrl,
                    "pretext" : "*Finding ID: " +  messageId + "*", 
                    "title" : finding,
                    "title_link" : consoleUrl,
                    "text" : findingDescription, 
                    "fields" : [ 
                        {"title" : "Severity", "value" : severity, "short" : True},
                        {"title" : "Region", "value" : region, "short" : True},
                        {"title" : "UpdatedAt", "value" : updatedAt, "short" : True},
                        {"title" : "Count", "value" : count, "short" : True}
                    ],
                    "mkdwn_in" : ["pretext"],
                    "color" : returnColor(severity),              
                }
            ]        
        }    

        if "sample" in event["service"]["additionalInfo"].keys():
             if event["service"]["additionalInfo"]["sample"] == True:
                #Test_Channel_URL
                webhook_url = "*"
                
        else:
            #DEV_Channel_URL
            webhook_url = "*"
        
        requests.post(
             webhook_url, data=json.dumps(slackPayloads),
             headers={'Content-Type': 'application/json'}
        )

        logger.info('SUCCESS: Pushed GuardDuty Finding to Slack')
        return "Successly pushed to Notification to Slack"
    except KeyError as e:
        logger.error('ERROR: Unable to push to Slack: Check [1] Slack Webhook URL is invalid, [2] IAM Role Permissions{0}'.format( str(e) ) )
        logger.error('ERROR: {0}'.format( str(e) ) )

def lambda_handler(event, context):
    return push_To_SNS_Topic(event)

if __name__ == '__main__':
    lambda_handler(None, None)
