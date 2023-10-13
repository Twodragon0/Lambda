# AWS API Real-time Monitoring

## Purpose
AWS operations are carried out through APIs, and the corresponding logs can be monitored through CloudTrail. This project aims to monitor essential information from CloudTrail logs for security and audit purposes.

## Progress

### Monitoring Flowchart
![Monitoring Flowchart](insert_flowchart_image_link_here)

### Monitoring Description
- All API requests generated in each AWS region are stored in Seoul Region S3 through CloudTrail.
- Logs stored in S3 are pulled into CloudWatch.
- A Lambda function, including specific conditions (e.g., SecurityGroup changes), is used to forward audit-related events to Slack.

### Monitored Targets
- Security Group (SecurityGroup) Configuration Changes (Yes)
- KMS Key Creation and Deletion (Yes)
- CloudTrail Changes (Yes)
- Console Login Failures (Yes)
- Authorization Failures (Yes)
- IAM Policy Changes (Yes)
- Network ACL (Access Control List) Changes (No)

### CloudWatch Events

#### Security Group (SecurityGroup) Configuration Changes
AWS SecurityGroup serves as a virtual firewall controlling inbound and outbound network traffic for instances. As part of firewall policy change monitoring, we aim to monitor SecurityGroup changes in real-time through Slack.

#### CloudWatch Events Rule Pattern
[Insert rule pattern here]

### SecurityGroup-Related API List
- AuthorizeSecurityGroupEgress: Add outbound rules
- AuthorizeSecurityGroupIngress: Add inbound rules
- RevokeSecurityGroupEgress: Modify or delete outbound rules
- RevokeSecurityGroupIngress: Modify or delete inbound rules
- CreateSecurityGroup: Create a new security group
- DeleteSecurityGroup: Delete a security group

## Lambda Source Code

1. [CloudTrail Audit Lambda Function](https://github.com/Twodragon0/Lambda/blob/main/Cloudtrail_Audit_lambda_function.py)
2. [SecurityGroup Lambda Function](https://github.com/Twodragon0/Lambda/blob/main/SG_lambda_function.py)
3. [General Lambda Function](https://github.com/Twodragon0/Lambda/blob/main/lambda_function.py)

## KMS Monitoring

### KMS-Related API List

- CreateKey → Key creation
- CreateAlias → Alias creation
- DisableKey → Key deactivation
- DeleteAlias → Alias deletion
- ScheduleKeyDeletion → Key deletion after a specified period

## Lambda Source Code

### CloudWatch Logs Subscriptions
Monitoring Targets:
- CloudTrail changes
- Authorization failures
- IAM policy changes
- Console login failures

### CloudTrail Changes

**Filter:**
{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}

### IAM Policy Changes

**Filter:**
{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}

### Console Login Failures

**Filter:**
{($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication")}

### After-Hours AWS Console Login Success

**CloudWatch Filter:**
{($.eventName = ConsoleLogin) && ($.responseElements.ConsoleLogin = "Success")}

## Note
Subscription filter has a 1024 character limit. NetworkACL monitoring is pending.
CloudTrail Configuration
