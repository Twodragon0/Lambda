import json
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

def consoleUrlReturn(awsRegion, eventID):
    url = "https://ap-northeast-2.console.aws.amazon.com/cloudtrail/home?region="
    consoleUrl = url + awsRegion + "#/events?EventId=" + eventID
    return consoleUrl

def lambda_handler(event, context):
    # Extract relevant information from the Session Manager event
    session_id = event['detail']['responseElements']['sessionId']
    # target_instance_id = event['detail']['requestParameters']['target']
    event_time = returnTime(event['detail']['eventTime'])
    event_name = event['detail']['eventName']
    awsRegion = event['detail']["awsRegion"]
    eventID = event['detail']["eventID"]
    consoleUrl = consoleUrlReturn(awsRegion, eventID)

    webhook_url = "*"

    slack_data = {
        "attachments": [
            {
                "pretext": "*Session Manager Event*",
                "title": "RawData",
                "title_link": consoleUrl,
                "fields": [
                    {"title": f"Session ID: {session_id}"},
                    {"title": "Event Time (KST)", "value": event_time, "short": True},
                    # {"title": "Target Instance ID", "value": target_instance_id, "short": True},
                    {"title": "Event Name", "value": event_name, "short": True},
                ],
                "color": "#00ffff",  # Default color
            }
        ]
    }

    response = requests.post(
        webhook_url, data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code != 200:
        raise ValueError(
            'Request to Slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
        )
