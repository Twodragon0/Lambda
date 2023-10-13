# Repository Information

This repository contains information related to the implementation of Amazon Systems Manager (SSM) on AWS and the associated security measures.

## Contents

- [Overview](#overview)
- [Background Knowledge](#background-knowledge)
- [Usage Plans](#usage-plans)
- [Security Measures](#security-measures)

## Overview

This document provides insights into the usage plans and security measures concerning the adoption of Amazon Systems Manager (SSM). The primary motivation behind this implementation is to replace 'login_duo' for SSH access and to facilitate secure management and maintenance of AWS instances.

## Background Knowledge

(Add any relevant background knowledge or context here.)

## Usage Plans

### Purpose

- Serve as an alternative server access method for instances, especially in the event of SSH or hardware failures.
- Enable infrastructure vulnerability scans through the execution of run commands, thus replacing the need for Ansible.
- Prepare for the potential role of hardware replacement.

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

4. **Considerations:**

   - Ensure that the `amazon-ssm-agent` version is 3.2.582.0 or higher.
   - IMDSv2 should be optional or required for the instances.
   - Due to AWS GUI limitations, configurations need to be made via the AWS CLI if using Systems Manager > Fleet Manager.
   - When KMS encryption is enabled, make sure to grant the necessary `kms:Decrypt` permissions.

## Security Measures

1. **SCP (Service Control Policy)**

   - Deny SSM actions (such as `StartSession` and `SendCommand`) for all IAM entities except for system-specific IAM entities.

2. **Session Encryption (KMS)**

   - Utilize AWS Key Management Service (KMS) for session encryption.

3. **Session Logging and Monitoring**

   - Set up monitoring for SSM actions, including `StartSession` and `RunCommand`, through Event Bridge.
   - Implement a log forwarding mechanism to send logs to Slack or other monitoring tools.

## Author

(Include your name or the author's name here, if applicable.)

