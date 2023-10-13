Information Paper: SSM Implementation and Security Measures on GitHub
1. Overview
This document outlines the plan for implementing Amazon System Manager (SSM) and associated security measures. The objective is to enhance the security and operational capabilities of AWS instances by installing the Amazon SSM agent. 
This will provide the ability to manage and control instances efficiently and securely.

2. Background Knowledge
Understanding of Amazon Web Services (AWS) infrastructure and IAM roles.
Familiarity with AWS Key Management Service (KMS) encryption.
Knowledge of SCP (Service Control Policy) and IAM policies.
Experience with AWS CloudTrail for monitoring and auditing.
Event Bridge usage for auditing and monitoring.


3. Usage Plan
Purpose:
Provide an alternative access method to instances when SSH or hardware issues arise.
Facilitate infrastructure vulnerability scanning through Run Command, replacing traditional methods like Ansible.
Serve as a potential hardware replacement solution.
Implementation Plan:
Install the Amazon SSM agent (version 3.2.582.0 or later) on all instances that require SSH access using Ansible.

Configure Session Manager Preferences:

Enable KMS encryption.
Utilize Session Manager with Custom Managed Keys (CMK).
Enable S3 and CloudTrail logging.
Set the default shell profile to /bin/bash (recommended), as the default shell is /bin/sh.
Grant the necessary IAM roles or configure DHMC (Default Host Management Configuration) settings for instances. This allows SSM Control and Data Channel to be opened for run commands and session initiation. DHMC settings can be applied through Session Manager basic IAM role configuration.

Reference: Amazon DHMC Configuration Guide
Additional permissions required: Create IAM Instance Profile for SSM Logging

Configure IAM permissions for users who will run commands and initiate sessions. Use the following IAM policy as an example:

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:StartSession",
                "ssm:SendCommand" 
            ],
            "Resource": [
                "arn:aws:ec2:region:account-id:instance/instance-id",
                "arn:aws:ssm:region:account-id:document/SSM-SessionManagerRunShell" 
            ],
            "Condition": {
                "BoolIfExists": {
                    "ssm:SessionDocumentAccessCheck": "true" 
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:TerminateSession",
                "ssm:ResumeSession"
            ],
            "Resource": [
                "arn:aws:ssm:*:*:session/${aws:userid}-*"
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:GenerateDataKey" 
            ],
            "Resource": "key-name"
        }
    ]
}

Reference: Restricting User Access to SSM

Execute Run Command to remove DUO authentication as required.

Consider using SSM sessions for hardware replacement and other management tasks.

4. Security Measures
Service Control Policy (SCP):

Apply a policy that denies SSM actions (StartSession, SendCommand) for all IAM entities except those designed for system use. This helps restrict unauthorized access to SSM functionality.
Example SCP Policy:

{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Deny",
         "Action": [
            "ssm:StartSession",
            "ssm:SendCommand"
         ],
         "Resource": "*",
         "Condition": {
            "ArnLike": {
               "aws:PrincipalArn": [
                  "arn:aws:iam::(account-ID):user/*",
                  "arn:aws:iam::(account-ID):group/*",
                  "arn:aws:iam::(account-ID):role/*"
               ]
            }
         }
      }
   ]
}

This policy denies SSM actions (such as session creation and command execution) for all IAM entities except for system-related IAM entities.

Session Encryption (KMS): Implement KMS encryption for session data. [Reference Documentation: Using Parameter Store]

Session Logging and Monitoring: Enable session logging and monitoring to ensure access control and audit trails. [Reference Documentation: Monitoring CloudTrail Logs]. Consider using Event Bridge for audit monitoring and sending logs to Slack for review.