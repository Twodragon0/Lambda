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

def handle_session_manager_event(event):
    # Extract relevant information from the Session Manager event
    session_id = event['responseElements']['sessionId']
#    target_instance_id = event['requestParameters']['target']
    event_time = returnTime(event['eventTime'])
    event_name = event['eventName']
    awsRegion = event["awsRegion"]
    eventID = event["eventID"]
    consoleUrl = consoleUrlReturn(awsRegion, eventID)


    # Check for 'StartSession', 'ResumeSession', and 'TerminateSession' events
    if event_name in ["StartSession", "ResumeSession", "TerminateSession"]:
        # Customize the message content for Session Manager events
        slack_data = {
            "attachments": [
                {
                    "pretext": "*Session Manager Event*",
                    "title" : "RawData",
                    "title_link" : consoleUrl,
                    "fields": [
                        {"title": f"Session ID: {session_id}"},
                        {"title": "Event Time (KST)", "value": event_time, "short": True},
#                        {"title": "Target Instance ID", "value": target_instance_id, "short": True},
                        {"title": "Event Name", "value": event_name, "short": True},
                    ],
                    "color": "#00ffff",  # Default color
                }
            ]
        }

        webhook_url = "https://hooks.slack.com/services/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"

        response = requests.post(
            webhook_url, data=json.dumps(slack_data),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code != 200:
            raise ValueError(
                'Request to Slack returned an error %s, the response is:\n%s'
                % (response.status_code, response.text)
            )

def lambda_handler(event, context):
    handle_session_manager_event(event['detail'])
