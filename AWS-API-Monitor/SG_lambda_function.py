import boto3, os, sys, json, logging, requests, datetime
 
 
# Set the log format
logger = logging.getLogger()
for h in logger.handlers:
  logger.removeHandler(h)
 
h = logging.StreamHandler(sys.stdout)
FORMAT = ' [%(levelname)s]/%(asctime)s/%(name)s - %(message)s'
h.setFormatter(logging.Formatter(FORMAT))
logger.addHandler(h)
logger.setLevel(logging.INFO)

# Slack
webhook_url = "*"

def returnTime(eventTime):
    eventTime = eventTime.split("T")
    date = eventTime[0]
    time = eventTime[1].split("Z")[0]
    ret_time = date + " " + time
    ret_time = datetime.datetime.strptime(ret_time, '%Y-%m-%d %H:%M:%S')
    ret_time = ret_time + datetime.timedelta(hours=9)  
     
    return str(ret_time)
 
def consoleUrlReturn(awsRegion, eventID):
    url = "https://ap-northeast-2.console.aws.amazon.com/cloudtrail/home?region="
    consoleUrl = url + awsRegion + "#/events?EventId=" + eventID
    return consoleUrl
 
 
def returnIpAddress(ipAddress):
    if "items" in ipAddress["ipRanges"]:
        ip = ipAddress["ipRanges"]["items"][0]["cidrIp"]
        des = returnDescription(ipAddress["ipRanges"]["items"][0])
 
    elif "items" in ipAddress["ipv6Ranges"]:
        ip = ipAddress["ipv6Ranges"]["items"][0]["cidrIpv6"]
        des = returnDescription(ipAddress["ipv6Ranges"]["items"][0])
 
    elif "items" in ipAddress["groups"] :
        ip = ipAddress["groups"]["items"][0]["groupId"]
        des = returnDescription(ipAddress["groups"]["items"][0])
 
    return ip, des
 
# if there is a description
def returnDescription(items):
    if "description" in items:
        des =  items["description"]
    else:
        des = " "
 
    return des
 
 
def lambda_handler(event, context):
    # [*] AWS Security Group APIs
    # 1. CreateSecurityGroup - Create a SecurityGroup
    # 2. DeleteSecurityGroup - Delete a SecurityGroup
    # 3. AuthorizeSecurityGroupIngress - Add an Inbound Rule
    # 4. AuthorizeSecurityGroupEgress - Add an Outbound Rule
    # 5. RevokeSecurityGroupIngress - Remove an Inbound Rule
    # 6. RevokeSecurityGroupEgress - Remove an Outbound Rule
 
    # Common Values
    apiName = event['detail']['eventName']
    accountId = event['detail']["userIdentity"]["accountId"]
    apiTime = returnTime(event['detail']["eventTime"])
    sourceIP = event['detail']["sourceIPAddress"]
    awsRegion = event['detail']["awsRegion"]
    eventID = event['detail']["eventID"]
    userName = event['detail']["userIdentity"]["userName"]
    consoleUrl = consoleUrlReturn(awsRegion,eventID)




    # CreateSecurityGroup
    if apiName == "CreateSecurityGroup":
        sgID = event['detail']["responseElements"]["groupId"]
        sgName = event['detail']["requestParameters"]["groupName"]

        slackPayloads = {
            "attachments" : [
                {
                    "pretext" : "*Security Group Changes Monitoring*",
                    "title" : "RawData",
                    "title_link" : consoleUrl,
                    "fields" : [
                        {"title" : "Event Name", "value" : apiName, "short" : True},
                        {"title" : "Account Id", "value" : accountId, "short" : True},
                        {"title" : "Event Time", "value" : apiTime, "short" : True},
                        {"title" : "Source IP", "value" : sourceIP, "short" : True},
                        {"title" : "User Name", "value" : userName, "short" : True},
                        {"title" : "SG ID", "value" : sgID, "short" : True},
                        {"title" : "SG Name", "value" : sgName, "short" : True},
                        {"title" : "AWS Region", "value" : awsRegion, "short" : True}
                    ],
                    "mkdwn_in" : ["pretext"],
                    "color" : "#3AA3E3",     
                }
            ]       
        }


    # DeleteSecurityGroup
    elif apiName == "DeleteSecurityGroup":
        sgID = event['detail']["requestParameters"]["groupId"]

        slackPayloads = {
            "attachments" : [
                {
                    "pretext" : "*Security Group Changes Monitoring*",
                    "title" : "RawData",
                    "title_link" : consoleUrl,
                    "fields" : [
                        {"title" : "Event Name", "value" : apiName, "short" : True},
                        {"title" : "Account Id", "value" : accountId, "short" : True},
                        {"title" : "Event Time", "value" : apiTime, "short" : True},
                        {"title" : "Source IP", "value" : sourceIP, "short" : True},
                        {"title" : "User Name", "value" : userName, "short" : True},
                        {"title" : "SG ID", "value" : sgID, "short" : True},
                        {"title" : "AWS Region", "value" : awsRegion, "short" : True}
                    ],
                    "mkdwn_in" : ["pretext"],
                    "color" : "#3AA3E3",     
                }
            ]       
        }           


    # AuthorizeSecurityGroupIngress              
    elif apiName == "AuthorizeSecurityGroupIngress":
        sgID = event['detail']["requestParameters"]["groupId"]
        info = ""

        if "items" in event['detail']['requestParameters']['ipPermissions']:
            for i in event['detail']['requestParameters']['ipPermissions']['items']:
                if "fromPort" in i and "toPort" in i and i["fromPort"] == i["toPort"]:
                    port = str(i["toPort"])
                    ip, des = returnIpAddress(i)
                    
                    info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Source: " + '%-21s' % ip + " Description: " + des+ "\n"
                        
                else:
                    port = str(i["fromPort"]) + " - " + str(i["toPort"])
                    ip, des = returnIpAddress(i)

                    info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Source: " + '%-21s' % ip + " Description: " + des+ "\n"
                        

                
            slackPayloads = {
                "attachments" : [
                    {
                        "pretext" : "*Security Group Changes Monitoring*",
                        "title" : "RawData",
                        "title_link" : consoleUrl,
                        "fields" : [
                            {"title" : "Event Name", "value" : apiName, "short" : True},
                            {"title" : "Account Id", "value" : accountId, "short" : True},
                            {"title" : "Event Time", "value" : apiTime, "short" : True},
                            {"title" : "Source IP", "value" : sourceIP, "short" : True},
                            {"title" : "User Name", "value" : userName, "short" : True},
                            {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                            {"title" : "SG ID", "value" : sgID, "short" : True},
                            {"title" : "Information", "value" : info}
                        ],
                        "mkdwn_in" : ["pretext"],
                        "color" : "#FF0000",     
                    }
                ]       
            }
        else:
            pass


        accountId = event['detail']['userIdentity']['accountId']
        #여기
        userName = event['detail']['userIdentity']['userName']
        sourceIP = event['detail']['sourceIPAddress']
        awsRegion = event['detail']['awsRegion']
        eventTime =(event['detail']['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (event['detail']['requestParameters']['groupId'])
        principalId = (event['detail']['userIdentity']['principalId'])
        arn = (event['detail']['userIdentity']['arn'])
        port = (event['detail']['requestParameters']['ipPermissions']['items'][0]['toPort'])
        protocol = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipProtocol'])
        ipv4 = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'])
        ipv6 = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'])

        try:
            description = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['description'])
        except KeyError as e:
            description = "None"
        
        IP_Port_Checker(event, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, port, description, ipv4, ipv6, userName)

        accountId = (event['detail']['userIdentity']['accountId'])
        userName = (event['detail']['userIdentity']['userName'])
        sourceIP = (event['detail']['sourceIPAddress'])
        awsRegion = (event['detail']['awsRegion'])
        eventTime =(event['detail']['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (event['detail']['requestParameters']['groupId'])
        principalId = (event['detail']['userIdentity']['principalId'])
        arn = (event['detail']['userIdentity']['arn'])
        toport = (event['detail']['requestParameters']['ipPermissions']['items'][0]['toPort'])
        fromport = (event['detail']['requestParameters']['ipPermissions']['items'][0]['fromPort'])
        protocol = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipProtocol'])
        ipv4 = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'])
        ipv6 = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'])

        try:
            description = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['description'])
        except KeyError as e:
            description = "None"

        IP_Port_Checker_zero(event, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, userName)

               
    # AuthorizeSecurityGroupEgress
    elif apiName == "AuthorizeSecurityGroupEgress":
        sgID = event['detail']["requestParameters"]["groupId"]
        info = ""

        if "items" in event['detail']['requestParameters']['ipPermissions']:
            for i in event['detail']['requestParameters']['ipPermissions']['items']:
                if "fromPort" in i and "toPort" in i and i["fromPort"] == i["toPort"]:
                    port = str(i["toPort"])
                    ip, des = returnIpAddress(i)
                    
                    info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Destination: " + '%-21s' % ip + " Description: " + des+ "\n"
                        
                else:
                    port = str(i["fromPort"]) + " - " + str(i["toPort"])
                    ip, des = returnIpAddress(i)

                    info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Destination: " + '%-21s' % ip + " Description: " + des+ "\n"
                
            slackPayloads = {
                "attachments" : [
                    {
                        "pretext" : "*Security Group Changes Monitoring*",
                        "title" : "RawData",
                        "title_link" : consoleUrl,
                        "fields" : [
                            {"title" : "Event Name", "value" : apiName, "short" : True},
                            {"title" : "Account Id", "value" : accountId, "short" : True},
                            {"title" : "Event Time", "value" : apiTime, "short" : True},
                            {"title" : "Source IP", "value" : sourceIP, "short" : True},
                            {"title" : "User Name", "value" : userName, "short" : True},
                            {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                            {"title" : "SG ID", "value" : sgID, "short" : True},
                            {"title" : "Information", "value" : info}
                        ],
                        "mkdwn_in" : ["pretext"],
                        "color" : "#0000FF",     
                    }
                ]       
            }
        else:
            pass

        accountId = (event['detail']['userIdentity']['accountId'])
        userName = (event['detail']['userIdentity']['userName'])
        sourceIP = (event['detail']['sourceIPAddress'])
        awsRegion = (event['detail']['awsRegion'])
        eventTime =(event['detail']['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (event['detail']['requestParameters']['groupId'])
        principalId = (event['detail']['userIdentity']['principalId'])
        arn = (event['detail']['userIdentity']['arn'])
        toport = (event['detail']['requestParameters']['ipPermissions']['items'][0]['toPort'])
        fromport = (event['detail']['requestParameters']['ipPermissions']['items'][0]['fromPort'])
        protocol = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipProtocol'])
        ipv4 = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'])
        ipv6 = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'])

        try:
            description = (event['detail']['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['description'])
        except KeyError as e:
            description = "None"

        IP_Port_Checker_zero(event, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, userName)


    # RevokeSecurityGroupIngress
    elif apiName == "RevokeSecurityGroupIngress":
        sgID = event['detail']["requestParameters"]["groupId"]
        info = ""


        if "items" in event['detail']['requestParameters']['ipPermissions']:
            for i in event['detail']['requestParameters']['ipPermissions']['items']:
                if "fromPort" in i and "toPort" in i and i["fromPort"] == i["toPort"]:
                    port = str(i["toPort"])
                    ip, des = returnIpAddress(i)
                    
                    info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Source: " + '%-21s' % ip + " Description: " + des+ "\n"
                        
                else:
                    port = str(i["fromPort"]) + " - " + str(i["toPort"])
                    ip, des = returnIpAddress(i)

                    info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Source: " + '%-21s' % ip + " Description: " + des+ "\n"
                
            slackPayloads = {
                "attachments" : [
                    {
                        "pretext" : "*Security Group Changes Monitoring*",
                        "title" : "RawData",
                        "title_link" : consoleUrl,
                        "fields" : [
                            {"title" : "Event Name", "value" : apiName, "short" : True},
                            {"title" : "Account Id", "value" : accountId, "short" : True},
                            {"title" : "Event Time", "value" : apiTime, "short" : True},
                            {"title" : "Source IP", "value" : sourceIP, "short" : True},
                            {"title" : "User Name", "value" : userName, "short" : True},
                            {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                            {"title" : "SG ID", "value" : sgID, "short" : True},
                            {"title" : "Information", "value" : info}
                        ],
                        "mkdwn_in" : ["pretext"],
                        "color" : "#FF0000",     
                    }
                ]       
            }   
        else:
            sgrID = ''
            sgrID_pool = ''
            try:
                for i in range(0, 64):
                    sgrID_pool = event['detail']['requestParameters']['securityGroupRuleIds']['items'][i]['securityGroupRuleId']
                    sgrID = '' + sgrID + " " + sgrID_pool
            except IndexError:
                pass
            info = info + "Remove SecurityGroupRuleId: " + sgrID  + "\n"
            slackPayloads = {
                "attachments" : [
                    {
                        "pretext" : "*Security Group Changes Monitoring*",
                        "title" : "RawData",
                        "title_link" : consoleUrl,
                        "fields" : [
                            {"title" : "Event Name", "value" : apiName, "short" : True},
                            {"title" : "Account Id", "value" : accountId, "short" : True},
                            {"title" : "Event Time", "value" : apiTime, "short" : True},
                            {"title" : "Source IP", "value" : sourceIP, "short" : True},
                            {"title" : "User Name", "value" : userName, "short" : True},
                            {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                            {"title" : "SG ID", "value" : sgID, "short" : True},
                            {"title" : "Information", "value" : info}
                        ],
                        "mkdwn_in" : ["pretext"],
                        "color" : "#FF0000",     
                    }
                ]       
            }    


    # RevokeSecurityGroupEgress
    elif apiName == "RevokeSecurityGroupEgress":
        sgID = event['detail']["requestParameters"]["groupId"]
        info = ""


        if "items" in event['detail']['requestParameters']['ipPermissions']:
            for i in event['detail']['requestParameters']['ipPermissions']['items']:
                if "fromPort" in i:
                    if i["fromPort"] == i["toPort"]:
                        port = str(i["toPort"])
                        ip, des = returnIpAddress(i)
                
                        info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Source: " + '%-21s' % ip + " Description: " + des+ "\n"
                    
                    else:
                        port = str(i["fromPort"]) + " - " + str(i["toPort"])
                        ip, des = returnIpAddress(i)

                        info = info + "Protocol: " + '%-10s' % i["ipProtocol"]  + "Port: " + '%-15s' % port  + "Source: " + '%-21s' % ip + " Description: " + des+ "\n"                  
            
                    slackPayloads = {
                        "attachments" : [
                            {
                                "pretext" : "*Security Group Changes Monitoring*",
                                "title" : "RawData",
                                "title_link" : consoleUrl,
                                "fields" : [
                                    {"title" : "Event Name", "value" : apiName, "short" : True},
                                    {"title" : "Account Id", "value" : accountId, "short" : True},
                                    {"title" : "Event Time", "value" : apiTime, "short" : True},
                                    {"title" : "Source IP", "value" : sourceIP, "short" : True},
                                    {"title" : "User Name", "value" : userName, "short" : True},
                                    {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                                    {"title" : "SG ID", "value" : sgID, "short" : True},
                                {"title" : "Information", "value" : info}
                                ],
                                "mkdwn_in" : ["pretext"],
                                "color" : "#0000FF",     
                            }
                        ]       
                    }
                else:
                    pass        
        else:
            sgrID = ''
            sgrID_pool = ''
            try:
                for i in range(0, 64):
                    sgrID_pool = event['detail']['requestParameters']['securityGroupRuleIds']['items'][i]['securityGroupRuleId']
                    sgrID = '' + sgrID + " " + sgrID_pool
            except IndexError:
                pass
            
            #sgrID = event['requestParameters']['securityGroupRuleIds']['items'][0]['securityGroupRuleId']
            info = info + "Remove SecurityGroupRuleId: " + sgrID  + "\n"
            slackPayloads = {
                "attachments" : [
                    {
                        "pretext" : "*Security Group Changes Monitoring*",
                        "title" : "RawData",
                        "title_link" : consoleUrl,
                        "fields" : [
                            {"title" : "Event Name", "value" : apiName, "short" : True},
                            {"title" : "Account Id", "value" : accountId, "short" : True},
                            {"title" : "Event Time", "value" : apiTime, "short" : True},
                            {"title" : "Source IP", "value" : sourceIP, "short" : True},
                            {"title" : "User Name", "value" : userName, "short" : True},
                            {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                            {"title" : "SG ID", "value" : sgID, "short" : True},
                            {"title" : "Information", "value" : info}
                        ],
                        "mkdwn_in" : ["pretext"],
                        "color" : "#3AA3E3",     
                    }
                ]       
            }    



    # ModifySecurityGroupRules
    elif apiName == "ModifySecurityGroupRules":
        sgID = event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["GroupId"]
        sgrID = event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRuleId"]
        CidrIpv4 = event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["CidrIpv4"]
        FromPort = event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["FromPort"]
        ToPort = event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["ToPort"]
        IpProtocol = event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["IpProtocol"]
        try:
            Description = event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["Description"]
        except KeyError as e:
            Description = "None"

        info = ""
        info = info + "IP: " + '%-10s' % CidrIpv4  + "       From_Port: " + '%-15s' % FromPort  + "To_Port: " + '%-21s' % ToPort + " Description: " + Description+ "\n"


        slackPayloads = {
            "attachments" : [
                {
                    "pretext" : "*Security Group Changes Monitoring*",
                    "title" : "RawData",
                    "title_link" : consoleUrl,
                    "fields" : [
                        {"title" : "Event Name", "value" : apiName, "short" : True},
                        {"title" : "Account Id", "value" : accountId, "short" : True},
                        {"title" : "Event Time", "value" : apiTime, "short" : True},
                        {"title" : "Target IP", "value" : sourceIP, "short" : True},
                        {"title" : "User Name", "value" : userName, "short" : True},
                        {"title" : "SG ID", "value" : sgID, "short" : True},
                        {"title" : "SGR ID", "value" : sgrID, "short" : True},
                        {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                        {"title" : "Information", "value" : info}
                    ],
                    "mkdwn_in" : ["pretext"],
                    "color" : "#3AA3E3",     
                }
            ]       
        }
    

        accountId = (event['detail']['userIdentity']['accountId'])
        userName = (event['detail']['userIdentity']['userName'])
        sourceIP = (event['detail']['sourceIPAddress'])
        awsRegion = (event['detail']['awsRegion'])
        eventTime =(event['detail']['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["GroupId"])
        principalId = (event['detail']['userIdentity']['principalId'])
        arn = (event['detail']['userIdentity']['arn'])
        toport = (event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['ToPort'])
        fromport = (event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['FromPort'])
        protocol = (event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['IpProtocol'])
        ipv4 = (event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['CidrIpv4'])
        ipv6 = "None"

        try:
            description = (event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["Description"])
        except KeyError as e:
            description = "None"

        IP_Port_Checker_zero(event, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, userName)


        accountId = (event['detail']['userIdentity']['accountId'])
        userName = (event['detail']['userIdentity']['userName'])
        sourceIP = (event['detail']['sourceIPAddress'])
        awsRegion = (event['detail']['awsRegion'])
        eventTime =(event['detail']['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["GroupId"])
        principalId = (event['detail']['userIdentity']['principalId'])
        arn = (event['detail']['userIdentity']['arn'])
        port = (event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['ToPort'])
        protocol = (event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['IpProtocol'])
        ipv4 = (event['detail']['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['CidrIpv4'])
        ipv6 = "None"

        try:
            description = (event['detail']["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["Description"])
        except KeyError as e:
            description = "None"
        
        IP_Port_Checker(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, port, description, ipv4, ipv6, userName)





    requests.post(
    webhook_url, data=json.dumps(slackPayloads),
    headers={'Content-Type': 'application/json'}
    )

    logger.info('SUCCESS: Security Group Change to Slack')
    return "Successly pushed to Notification to Slack"

 

def IP_Port_Checker(event, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, port, description, ipv4, ipv6, userName):
    # if 'oneid' in arn:
    #     Username = principalId.split(':')[1]
    # else:
    username_imsi = arn.split('/')[1]
    username = username_imsi.split('@')[0]


    #.format(Username, accountId_list.accountId_find(accountId), awsRegion, groupId))
    if (port not in [80, 443, 8080, ]):
        if (ipv4 == '0.0.0.0/0' or ipv6 =='::/0' in ipv4):
            sourceIP = '0.0.0.0/0'
            Message_data = {
   "blocks": [
      {
         "type": "header",
         "text": {
            "type": "plain_text",
            "text": "Security Group 인바운드 ANY 포트 오픈",
            "emoji": True
         }
      },
      {
         "type": "section",
         "fields": [
            {
               "type": "mrkdwn",
               "text": f"*SecurityGroupID*\n<https://ap-northeast-2.console.aws.amazon.com/ec2/v2/home?region=ap-northeast-2#SecurityGroup:groupId={groupId}|{groupId}>"
            },
            {
               "type": "mrkdwn",
               "text": f"*UserID*\n{userName}"
            }
         ]
      },
      {
         "type": "section",
         "fields": [
            {
               "type": "mrkdwn",
               "text": f"*Information*\n Target Port: {port}"
            },
            {
               "type": "mrkdwn",
               "text": f"*Protocol*\n{protocol}"
            }
         ]
      },
      {
         "type": "section",
         "fields": [
            {
               "type": "mrkdwn",
               "text": f"*CreateTime*\n{apiTime}"
            },
            {
               "type": "mrkdwn",
               "text": f"*Description*\n{description}"
            }
         ]
      },
        {
         "type": "section",
         "text": {
            "type": "mrkdwn",
            "text": "*Notice*"
         }
      },
        {
         "type": "section",
         "text": {
            "type": "mrkdwn",
            "text": f"@{userName}, \n 이벤트 확인 후 해당 Rule 삭제 혹은 출발지 지정 부탁 드립니다. \n 요청에 의한 오픈인 경우, 완료 이모지 부탁 드립니다. (ModifyS/G Outbound는 오탐있음) \n"         } 
      }
   ]
}
            Send_Message(Message_data)
        else:
            pass
    else:
        pass









def IP_Port_Checker_zero(event, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, userName):
    # if 'oneid' in arn:
    #     Username = principalId.split(':')[1]
    # else:
    username_imsi = arn.split('/')[1]
    username = username_imsi.split('@')[0]
 
    #.format(Username, accountId_list.accountId_find(accountId), awsRegion, groupId))
    if (fromport == 0 or toport == 0):
 
        Message_data = {
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "SecurityGroup 포트 0번 오픈?!",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*SecurityGroupID*\n<https://ap-northeast-2.console.aws.amazon.com/ec2/v2/home?region=ap-northeast-2#SecurityGroup:groupId={groupId}|{groupId}>"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*UserID*\n{userName}"
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Information*\n IP: {ipv4}   Port: {toport}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Protocol*\n{protocol}"
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*CreateTime*\n{apiTime}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Description*\n{description}"
                }
            ]
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*Notice*"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"@{userName}, \n 이벤트 확인 후 해당 Rule의 포트 재지정 부탁 드립니다. \n 확인이 끝난 경우 완료 이모지 부탁 드립니다."
            }
        }
    ]
}
        Send_Message(Message_data)
    else:
        pass


def Send_Message(slack_message):
    req = requests.post(webhook_url, data = json.dumps(slack_message), headers={'Content-Type': 'application/json'})
