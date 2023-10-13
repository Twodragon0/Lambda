# Repository Information

This repository contains information related to the implementation of Amazon Systems Manager (SSM) on AWS and the associated security measures.

## Contents

- [Overview](#overview)
- [Background Knowledge](#background-knowledge)
- [Usage Plans](#usage-plans)
- [Security Measures](#security-measures)

## Overview

This document outlines the plan for implementing Amazon System Manager (SSM) and associated security measures. 
The objective is to enhance the security and operational capabilities of AWS instances by installing the Amazon SSM agent. 
This will provide the ability to manage and control instances efficiently and securely.


## Background Knowledge

- Understanding of Amazon Web Services (AWS) infrastructure and IAM roles.
- Familiarity with AWS Key Management Service (KMS) encryption.
- Knowledge of SCP (Service Control Policy) and IAM policies.
- Experience with AWS CloudTrail for monitoring and auditing.
- Event Bridge usage for auditing and monitoring.

## Usage Plans

### Purpose:

- Provide an alternative access method to instances when SSH or hardware issues arise.
- Facilitate infrastructure vulnerability scanning through Run Command, replacing traditional methods like Ansible.
- Serve as a potential hardware replacement solution.

### Usage Plan

1. **Installation of `amazon-ssm-agent`:** Install the `amazon-ssm-agent` on all instances requiring SSH access using Ansible. Ensure that the agent version is 3.2.582.0 or later.

2. **Session Manager Preferences Setting:**

   - **KMS Encryption:** Enable KMS encryption using a Session Manager-specific Customer Master Key (CMK).
   - **S3 Logging:** Activate S3 logging.
   - **CloudTrail Logging:** Enable CloudTrail logging.
   - **Shell Profile:** Use `/bin/bash` as the recommended shell profile, with `/bin/sh` as the default shell.

3. **IAM Role or DHMC Configuration for Target Instances:**

   - To enable SSM Control and Data Channel on target instances for run command and session initiation, ensure that the instance's IAM role has the `AmazonSSMManagedInstanceCore` role or follow the DHMC (Default Host Management Configuration) settings for the necessary permissions.

   - [DHMC Configuration](https://aws.amazon.com/ko/blogs/mt/enable-management-of-your-amazon-ec2-instances-in-aws-systems-manager-using-default-host-management-configuration/)

   - Additional Permissions Required: [IAM Instance Profile Creation](https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-create-iam-instance-profile.html#create-iam-instance-profile-ssn-logging)
   -  [IAM policy as an example](https://github.com/Twodragon0/Lambda/blob/7adbfc226d26f3c53b1060d22271cd17efd16f57/SSM/IAM_policy.json)

4. **Considerations:**

   - Ensure that the `amazon-ssm-agent` version is 3.2.582.0 or higher.
   - IMDSv2 should be optional or required for the instances.
   - Due to AWS GUI limitations, configurations need to be made via the AWS CLI if using Systems Manager > Fleet Manager.
   - When KMS encryption is enabled, make sure to grant the necessary `kms:Decrypt` permissions.

## Security Measures

### SCP (Service Control Policy) :

   - Deny SSM actions (such as `StartSession` and `SendCommand`) for all IAM entities except for system-specific IAM entities.
   - [Example SCP Policy](https://github.com/Twodragon0/Lambda/blob/7adbfc226d26f3c53b1060d22271cd17efd16f57/SSM/SCP_Policy.json)

### Session Encryption (KMS):

- Implement KMS encryption for session data.

- **Reference Documentation:** [Using Parameter Store](https://docs.aws.amazon.com/ko_kr/kms/latest/developerguide/services-parameter-store.html)

### Session Logging and Monitoring:

- Enable session logging and monitoring to ensure access control and audit trails.

- **Reference Documentation:** [Monitoring CloudTrail Logs](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html)

- Consider using Event Bridge for audit monitoring and sending logs to Slack for review.

## Author

@twodragon

