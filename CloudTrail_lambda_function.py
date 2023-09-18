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
 
 
def push_To_Slack_SG_Change(event):
    # [*] AWS Security Group APIs
    # 1. CreateSecurityGroup - Create a SecurityGroup
    # 2. DeleteSecurityGroup - Delete a SecurityGroup
    # 3. AuthorizeSecurityGroupIngress - Add an Inbound Rule
    # 4. AuthorizeSecurityGroupEgress - Add an Outbound Rule
    # 5. RevokeSecurityGroupIngress - Remove an Inbound Rule
    # 6. RevokeSecurityGroupEgress - Remove an Outbound Rule
 

    # Slack
    # Common Values
    apiName = event['eventName']
    accountId = event["userIdentity"]["accountId"]
    apiTime = returnTime(event["eventTime"])
    srcIp = event["sourceIPAddress"]
    awsRegion = event["awsRegion"]
    eventID = event["eventID"]
    usrName = event["userIdentity"]["userName"]
    consoleUrl = consoleUrlReturn(awsRegion,eventID)




    # CreateSecurityGroup
    if apiName == "CreateSecurityGroup":
        sgID = event["responseElements"]["groupId"]
        sgName = event["requestParameters"]["groupName"]

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
                        {"title" : "Source IP", "value" : srcIp, "short" : True},
                        {"title" : "User Name", "value" : usrName, "short" : True},
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
        sgID = event["requestParameters"]["groupId"]

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
                        {"title" : "Source IP", "value" : srcIp, "short" : True},
                        {"title" : "User Name", "value" : usrName, "short" : True},
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
        sgID = event["requestParameters"]["groupId"]
        info = ""

        if "items" in event['requestParameters']['ipPermissions']:
            for i in event['requestParameters']['ipPermissions']['items']:
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
                            {"title" : "Source IP", "value" : srcIp, "short" : True},
                            {"title" : "User Name", "value" : usrName, "short" : True},
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



        data = event
        accountId = (data['userIdentity']['accountId'])
        #여기
        Username = (data['userIdentity']['userName'])
        sourceIP = (data['sourceIPAddress'])
        awsRegion = (data['awsRegion'])
        eventTime =(data['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (data['requestParameters']['groupId'])
        principalId = (data['userIdentity']['principalId'])
        arn = (data['userIdentity']['arn'])
        port = (data['requestParameters']['ipPermissions']['items'][0]['toPort'])
        protocol = (data['requestParameters']['ipPermissions']['items'][0]['ipProtocol'])
        ipv4 = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'])
        ipv6 = (data['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'])

        try:
            description = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['description'])
        except KeyError as e:
            description = "None"
        
        IP_Port_Checker(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, port, description, ipv4, ipv6, Username)


        data = event
        accountId = (data['userIdentity']['accountId'])
        Username = (data['userIdentity']['userName'])
        sourceIP = (data['sourceIPAddress'])
        awsRegion = (data['awsRegion'])
        eventTime =(data['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (data['requestParameters']['groupId'])
        principalId = (data['userIdentity']['principalId'])
        arn = (data['userIdentity']['arn'])
        toport = (data['requestParameters']['ipPermissions']['items'][0]['toPort'])
        fromport = (data['requestParameters']['ipPermissions']['items'][0]['fromPort'])
        protocol = (data['requestParameters']['ipPermissions']['items'][0]['ipProtocol'])
        ipv4 = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'])
        ipv6 = (data['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'])

        try:
            description = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['description'])
        except KeyError as e:
            description = "None"

        IP_Port_Checker_zero(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, Username)

               
    # AuthorizeSecurityGroupEgress
    elif apiName == "AuthorizeSecurityGroupEgress":
        sgID = event["requestParameters"]["groupId"]
        info = ""

        if "items" in event['requestParameters']['ipPermissions']:
            for i in event['requestParameters']['ipPermissions']['items']:
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
                            {"title" : "Source IP", "value" : srcIp, "short" : True},
                            {"title" : "User Name", "value" : usrName, "short" : True},
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

        data = event
        accountId = (data['userIdentity']['accountId'])
        Username = (data['userIdentity']['userName'])
        sourceIP = (data['sourceIPAddress'])
        awsRegion = (data['awsRegion'])
        eventTime =(data['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (data['requestParameters']['groupId'])
        principalId = (data['userIdentity']['principalId'])
        arn = (data['userIdentity']['arn'])
        toport = (data['requestParameters']['ipPermissions']['items'][0]['toPort'])
        fromport = (data['requestParameters']['ipPermissions']['items'][0]['fromPort'])
        protocol = (data['requestParameters']['ipPermissions']['items'][0]['ipProtocol'])
        ipv4 = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['cidrIp'])
        ipv6 = (data['requestParameters']['ipPermissions']['items'][0]['ipv6Ranges'])

        try:
            description = (data['requestParameters']['ipPermissions']['items'][0]['ipRanges']['items'][0]['description'])
        except KeyError as e:
            description = "None"

        IP_Port_Checker_zero(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, Username)


    # RevokeSecurityGroupIngress
    elif apiName == "RevokeSecurityGroupIngress":
        sgID = event["requestParameters"]["groupId"]
        info = ""


        if "items" in event['requestParameters']['ipPermissions']:
            for i in event['requestParameters']['ipPermissions']['items']:
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
                            {"title" : "Source IP", "value" : srcIp, "short" : True},
                            {"title" : "User Name", "value" : usrName, "short" : True},
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
                    sgrID_pool = event['requestParameters']['securityGroupRuleIds']['items'][i]['securityGroupRuleId']
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
                            {"title" : "Source IP", "value" : srcIp, "short" : True},
                            {"title" : "User Name", "value" : usrName, "short" : True},
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
        sgID = event["requestParameters"]["groupId"]
        info = ""


        if "items" in event['requestParameters']['ipPermissions']:
            for i in event['requestParameters']['ipPermissions']['items']:
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
                                    {"title" : "Source IP", "value" : srcIp, "short" : True},
                                    {"title" : "User Name", "value" : usrName, "short" : True},
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
                    sgrID_pool = event['requestParameters']['securityGroupRuleIds']['items'][i]['securityGroupRuleId']
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
                            {"title" : "Source IP", "value" : srcIp, "short" : True},
                            {"title" : "User Name", "value" : usrName, "short" : True},
                            {"title" : "AWS Region", "value" : awsRegion, "short" : True},
                            {"title" : "SG ID", "value" : sgID, "short" : True},
                            {"title" : "Information", "value" : info}
                        ],
                        "mkdwn_in" : ["pretext"],
                        "color" : "#3AA3E3",     
                    }
                ]       
            }    



# 여기서부터 수정

    # ModifySecurityGroupRules
    elif apiName == "ModifySecurityGroupRules":
        sgID = event["requestParameters"]["ModifySecurityGroupRulesRequest"]["GroupId"]
        sgrID = event["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRuleId"]
        CidrIpv4 = event["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["CidrIpv4"]
        FromPort = event["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["FromPort"]
        ToPort = event["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["ToPort"]
        IpProtocol = event["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["IpProtocol"]
        try:
            Description = event["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["Description"]
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
                        {"title" : "Target IP", "value" : srcIp, "short" : True},
                        {"title" : "User Name", "value" : usrName, "short" : True},
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
    






        data = event
        accountId = (data['userIdentity']['accountId'])
        Username = (data['userIdentity']['userName'])
        sourceIP = (data['sourceIPAddress'])
        awsRegion = (data['awsRegion'])
        eventTime =(data['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (data["requestParameters"]["ModifySecurityGroupRulesRequest"]["GroupId"])
        principalId = (data['userIdentity']['principalId'])
        arn = (data['userIdentity']['arn'])
        toport = (data['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['ToPort'])
        fromport = (data['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['FromPort'])
        protocol = (data['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['IpProtocol'])
        ipv4 = (data['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['CidrIpv4'])
        ipv6 = "None"

        try:
            description = (data["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["Description"])
        except KeyError as e:
            description = "None"

        IP_Port_Checker_zero(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, Username)







        data = event
        accountId = (data['userIdentity']['accountId'])
        Username = (data['userIdentity']['userName'])
        sourceIP = (data['sourceIPAddress'])
        awsRegion = (data['awsRegion'])
        eventTime =(data['eventTime'])
        apiTime = returnTime(eventTime)
        groupId = (data["requestParameters"]["ModifySecurityGroupRulesRequest"]["GroupId"])
        principalId = (data['userIdentity']['principalId'])
        arn = (data['userIdentity']['arn'])
        port = (data['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['ToPort'])
        protocol = (data['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['IpProtocol'])
        ipv4 = (data['requestParameters']['ModifySecurityGroupRulesRequest']['SecurityGroupRule']['SecurityGroupRule']['CidrIpv4'])
        ipv6 = "None"

        try:
            description = (data["requestParameters"]["ModifySecurityGroupRulesRequest"]["SecurityGroupRule"]["SecurityGroupRule"]["Description"])
        except KeyError as e:
            description = "None"
        
        IP_Port_Checker(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, port, description, ipv4, ipv6, Username)





    requests.post(
    webhook_url, data=json.dumps(slackPayloads),
    headers={'Content-Type': 'application/json'}
    )

    logger.info('SUCCESS: Security Group Change to Slack')
    return "Successly pushed to Notification to Slack"

 

def IP_Port_Checker(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, port, description, ipv4, ipv6, Username):
    # if 'oneid' in arn:
    #     Username = principalId.split(':')[1]
    # else:
    username_imsi = arn.split('/')[1]
    username = username_imsi.split('@')[0]


    #notice = ("<@>님, 계정 리전의 에 대해 삭제 혹은 출발지 지정 바랍니다." .format(Username, accountId_list.accountId_find(accountId), awsRegion, groupId))
    if (port not in [80, 443, 8080, ]):
        if (ipv4 == '0.0.0.0/0' or ipv6 =='::/0' in ipv4):
            srcip = '0.0.0.0/0'
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
               "text": f"*UserID*\n{Username}"
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
            "text": f"@{username}, \n 이벤트 확인 후 해당 Rule 삭제 혹은 출발지 지정 부탁 드립니다. \n 요청에 의한 오픈인 경우, 완료 이모지 부탁 드립니다. (ModifyS/G Outbound는 오탐있음) \n"         } 
      }
   ]
}
            Send_Message(Message_data)
        else:
            pass
    else:
        pass









def IP_Port_Checker_zero(data, arn, principalId, accountId, sourceIP, awsRegion, apiTime, groupId, protocol, toport, fromport, description, ipv4, ipv6, Username):
    # if 'oneid' in arn:
    #     Username = principalId.split(':')[1]
    # else:
    username_imsi = arn.split('/')[1]
    username = username_imsi.split('@')[0]
 
    #notice = ("<@>님, 계정 리전의 에 대해 삭제 혹은 출발지 지정 바랍니다." .format(Username, accountId_list.accountId_find(accountId), awsRegion, groupId))
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
                    "text": f"*UserID*\n{Username}"
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
                "text": f"@{username}, \n 이벤트 확인 후 해당 Rule의 포트 재지정 부탁 드립니다. \n 확인이 끝난 경우 완료 이모지 부탁 드립니다."
            }
        }
    ]
}
        Send_Message(Message_data)
    else:
        pass


def Send_Message(slack_message):
    req = requests.post(webhook_url, data = json.dumps(slack_message), headers={'Content-Type': 'application/json'})

 
def lambda_handler(event, context):
    return push_To_Slack_SG_Change(event['detail'])
 
if __name__ == '__main__':
    lambda_handler(None, None)
