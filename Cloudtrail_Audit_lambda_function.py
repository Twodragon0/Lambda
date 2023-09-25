import boto3, os, sys, json, logging,requests, datetime, base64, zlib 

# Set the log format
logger = logging.getLogger()
for h in logger.handlers:
  logger.removeHandler(h)

h = logging.StreamHandler(sys.stdout)
FORMAT = ' [%(levelname)s]/%(asctime)s/%(name)s - %(message)s'
h.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(h)
logger.setLevel(logging.INFO)

#If eventTime is in working time, this funtion return "True". If not, return "False"  
def workingTimeChecker(eventTime):
    time = int(eventTime.split()[1].split(":")[0])
    eventTimeDateForm = datetime.datetime.fromisoformat(eventTime)
    dayOfTheWeek = datetime.date.weekday(eventTimeDateForm)
    
    # Saturday: 5, Sunday: 6  
    if dayOfTheWeek == 5 or dayOfTheWeek == 6:
        return False 
        
    if 8 <= time <= 21:
        return True   
    else:
        return False

def consoleUrlReturn(awsRegion, eventID):
    url = "https://ap-northeast-2.console.aws.amazon.com/cloudtrail/home?region="
    consoleUrl = url + awsRegion + "#/events?EventId=" + eventID
    return consoleUrl

def returnTime(eventTime):
    eventTime = eventTime.split("T")
    date = eventTime[0]
    time = eventTime[1].split("Z")[0]
    ret_time = date + " " + time
    ret_time = datetime.datetime.strptime(ret_time, '%Y-%m-%d %H:%M:%S')
    ret_time = ret_time + datetime.timedelta(hours=9)   
    
    return str(ret_time)

def setSubject(rawData):
    subject = ""
    cloudTrailChanges_Filter = ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"]
    iamPolicyChanges_Filter = ["DeleteGroupPolicy","DeleteRolePolicy","DeleteUserPolicy","PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy"]

    if rawData['eventName'] in cloudTrailChanges_Filter:
        subject = "CloudTrail Changes"
        cloudTrailChanges(rawData,subject)

    elif rawData['eventName'] in iamPolicyChanges_Filter:
        subject = "IAM Policy Changes"
        iamPolicyChanges(rawData,subject)
        
    elif rawData['eventName'] == "ConsoleLogin" and rawData['responseElements']['ConsoleLogin'] == "Success":
        subject = "Console Sign-In druing not working time"
        signInDruingNotWorikingTime(rawData,subject)
        
    elif rawData['eventName'] == "ConsoleLogin" and rawData['errorMessage'] == "Failed authentication":
        sourceIPAddress=rawData['sourceIPAddress']
        excluded_ips=["1.1.1.1", "8.8.8.8"]
        if sourceIPAddress not in excluded_ips:
            subject = "Console Sign-In Failures (Non-specific Source IP)"
            consoleSignInFailures(rawData, subject)
        
    
    elif "UnauthorizedOperation" in rawData["errorCode"] or "AccessDenied" in rawData["errorCode"]:
        subject = "Authorization Failures"
        authorizationFailures(rawData,subject)

    return subject
    
def signInDruingNotWorikingTime(rawData, subject): 
    subject = "*" + subject + "*"
    eventName = rawData["eventName"]
    userAgent = rawData["userAgent"]
    sourceIPAddress = rawData["sourceIPAddress"]
    status = rawData['responseElements']['ConsoleLogin']
    userName = rawData["userIdentity"]["userName"]
    eventTime = returnTime(rawData["eventTime"])
    awsRegion = rawData["awsRegion"]
    eventID = rawData["eventID"]
    consoleUrl = consoleUrlReturn(awsRegion,eventID)


    #Working Time Check 
    if(workingTimeChecker(eventTime)):
        return
    
    slackPayloads = {
        "attachments" : [
            {
                "pretext" : subject,
                "title" : "RawData",
                "title_link" : consoleUrl,
                "fields" : [ 
                    {"title" : "Event Name", "value" : eventName, "short" : True},
                    {"title" : "Event Time", "value" : eventTime, "short" : True},
                    {"title" : "Source IP", "value" : sourceIPAddress, "short" : True},
                    {"title" : "User Name", "value" : userName, "short" : True},
                    {"title" : "User Agent", "value" : userAgent, "short" : True},
                    {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                    {"title" : "Status", "value" : status, "short" : True},
                    
                ],
                "mkdwn_in" : ["pretext"],
                "color" : "#FF0000",      
            }
        ]        
    }        
    
    
    #Webhook 
    webhook_url = "*"

    requests.post(
            webhook_url, data=json.dumps(slackPayloads),
            headers={'Content-Type': 'application/json'}
    )    

    #change the subject to directly notify the user 
    slackPayloads["attachments"][0]["pretext"] = "*업무시간 외 AWS 로그인이 확인되었습니다.*\n*본인이 로그인한 것이 아니라면 \"\"으로 즉시 신고 부탁드립니다.*"
    
    
    #Slack Bot Token 
    slackToken = "*"
        
    #Slack API URL - users.lookupByEmail 
    lookUpByEmail = "*"

    paramsForPayload = {
        "token" : slackToken, 
        "email" : userName
    }
     
    #To retrieve User ID by using Email address  
    res = requests.get(lookUpByEmail, params=paramsForPayload)
    
    #User ID 
    userID = res.json()['user']['id']   

    #Slack API URL - users.lookupByEmail 
    chatPostMessage = "*"

    person_data = {
        'token': slackToken,
        'channel': userID,  
        'as_user': True,
        "attachments" : json.dumps(slackPayloads["attachments"])
    }

    requests.post(chatPostMessage, data=person_data) 


    logger.info('SUCCESS: signInDruingNotWorikingTime to Slack')            
    return "Successly pushed to Notification to Slack"

def iamPolicyChanges(rawData, subject):
    subject = "*" + subject + "*"
    eventName = rawData["eventName"]
    sourceIPAddress = rawData["sourceIPAddress"]
    userName = rawData["userIdentity"]["userName"]
    eventTime = returnTime(rawData["eventTime"])
    awsRegion = rawData["awsRegion"]
    eventID = rawData["eventID"]
    consoleUrl = consoleUrlReturn(awsRegion, eventID)

    # Extract and format the requestParameters JSON
    requestParameters = rawData.get('requestParameters', {})
    formatted_request_parameters = json.dumps(
        requestParameters, indent=4, separators=(',', ': '))

    slackPayloads = {
        "attachments": [
            {
                "pretext": subject,
                "title": "RawData",
                "title_link": consoleUrl,
                "fields": [
                    {"title": "Event Name", "value": eventName, "short": True},
                    {"title": "Event Time", "value": eventTime, "short": True},
                    {"title": "Source IP", "value": sourceIPAddress, "short": True},
                    {"title": "User Name", "value": userName, "short": True},
                    {"title": "AWS Region", "value": awsRegion, "short": True},
                    {"title": "Request Parameters", "value": "```\n" + formatted_request_parameters + "\n```", "short": False},
                ],
                "mrkdwn_in": ["pretext"],
                "color": "#00FF00",
            }
        ]
    }

# Example usage:
# rawData = ... # Your rawData dictionary
# subject = "Policy Change"
# iamPolicyChanges(rawData, subject)

      
    webhook_url = "*"

    requests.post(
            webhook_url, data=json.dumps(slackPayloads),
            headers={'Content-Type': 'application/json'}
    )

    logger.info('SUCCESS: Audit log to Slack')            
    return "Successly pushed to Notification to Slack"


def cloudTrailChanges(rawData, subject):  
    subject = "*" + subject + "*"
    eventName = rawData["eventName"]
    sourceIPAddress = rawData["sourceIPAddress"]
    userName = rawData["userIdentity"]["userName"]
    eventTime = returnTime(rawData["eventTime"])
    awsRegion = rawData["awsRegion"]
    eventID = rawData["eventID"]
    consoleUrl = consoleUrlReturn(awsRegion,eventID)
    
    if 'name' in rawData['requestParameters']: 
        requestParam_Name = rawData['requestParameters']['name']
    else:
        requestParam_Name = "There is no filed in requestParameters" 

    slackPayloads = {
        "attachments" : [
            {
                "pretext" : subject,
                "title" : "RawData",
                "title_link" : consoleUrl,
                "fields" : [ 
                    {"title" : "Event Name", "value" : eventName, "short" : True},
                    {"title" : "Event Time", "value" : eventTime, "short" : True},
                    {"title" : "Source IP", "value" : sourceIPAddress, "short" : True},
                    {"title" : "User Name", "value" : userName, "short" : True},
                    {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                    {"title" : "Trail Name", "value" : requestParam_Name, "short" : True},
                    
                ],
                "mkdwn_in" : ["pretext"],
                "color" : "#0000FF",      
            }
        ]        
    }        

    webhook_url = "*"

    requests.post(
            webhook_url, data=json.dumps(slackPayloads),
            headers={'Content-Type': 'application/json'}
    )

    logger.info('SUCCESS: cloudTrailChanges Change to Slack')            
    return "Successly pushed to Notification to Slack"


def authorizationFailures(rawData, subject): 
    subject = "*" + subject + "*"
    eventName = rawData["eventName"]
    errorCode = rawData["errorCode"]
    sourceIPAddress = rawData["sourceIPAddress"]
    eventSource = rawData["eventSource"]
    errorMessage = rawData["errorMessage"]
    userName = rawData["userIdentity"]["userName"]
    eventTime = returnTime(rawData["eventTime"])
    awsRegion = rawData["awsRegion"]
    eventID = rawData["eventID"]
    consoleUrl = consoleUrlReturn(awsRegion,eventID)

    if(workingTimeChecker(eventTime)):
        return

    slackPayloads = {
        "attachments" : [
            {
                "pretext" : subject,
                "title" : "RawData",
                "title_link" : consoleUrl,
                "fields" : [ 
                    {"title" : "Event Name", "value" : eventName, "short" : True},
                    {"title" : "Event Time", "value" : eventTime, "short" : True},
                    {"title" : "Source IP", "value" : sourceIPAddress, "short" : True},
                    {"title" : "User Name", "value" : userName, "short" : True},
                    {"title" : "Error Code", "value" : errorCode, "short" : True},
                    {"title" : "Event Source", "value" : eventSource, "short" : True},
                    {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                    {"title" : "Error Message", "value" : errorMessage, "short" : True},
                    
                ],
                "mkdwn_in" : ["pretext"],
                "color" : "#3AA3E3",      
            }
        ]        
    }        

    webhook_url = "*"

    requests.post(
            webhook_url, data=json.dumps(slackPayloads),
            headers={'Content-Type': 'application/json'}
    )

    logger.info('SUCCESS: authorizationFailures to Slack')            
    return "Successly pushed to Notification to Slack"

def consoleSignInFailures(rawData, subject): 
    subject = "*" + subject + "*"
    eventName = rawData["eventName"]
    userAgent = rawData["userAgent"]
    sourceIPAddress = rawData["sourceIPAddress"]
    errorMessage = rawData["errorMessage"]
    userName = rawData["userIdentity"]["userName"]
    eventTime = returnTime(rawData["eventTime"])
    awsRegion = rawData["awsRegion"]
    eventID = rawData["eventID"]
    consoleUrl = consoleUrlReturn(awsRegion,eventID)
    
    slackPayloads = {
        "attachments" : [
            {
                "pretext" : subject,
                "title" : "RawData",
                "title_link" : consoleUrl,
                "fields" : [ 
                    {"title" : "Event Name", "value" : eventName, "short" : True},
                    {"title" : "Event Time", "value" : eventTime, "short" : True},
                    {"title" : "Source IP", "value" : sourceIPAddress, "short" : True},
                    {"title" : "User Name", "value" : userName, "short" : True},
                    {"title" : "User Agent", "value" : userAgent, "short" : True},
                    {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                    {"title" : "Error Message", "value" : errorMessage, "short" : True},
                    
                ],
                "mkdwn_in" : ["pretext"],
                "color" : "#FF0000",      
            }
        ]        
    }        

    webhook_url = "*"

    requests.post(
            webhook_url, data=json.dumps(slackPayloads),
            headers={'Content-Type': 'application/json'}
    )

    logger.info('SUCCESS: consoleSignInFailures to Slack')            
    return "Successly pushed to Notification to Slack"

def lambda_handler(event, context):
    
    try:
        # Get the Streamed data. It is Base64 Encoded and GZIP compressed
        encoded=event['awslogs']['data']
        # decode the logdata
        decoded_data = base64.b64decode(encoded)
        # decompress the decoded log data
        decompressed_data = zlib.decompress(decoded_data, 16+zlib.MAX_WBITS)
        decompressed_data = json.loads(decompressed_data)  

        for result in range(len(decompressed_data['logEvents'])) :
            rawData = json.loads(decompressed_data['logEvents'][result]['message'])
            setSubject(rawData)     
            
        return "Successly pushed to Notification"

    except KeyError as e:
        logger.error('ERROR: Unable to push to Slack: Check [1] Slack Webhook URL is invalid, [2] IAM Role Permissions{0}'.format( str(e) ) )
        logger.error('ERROR: {0}'.format( str(e) ) )
