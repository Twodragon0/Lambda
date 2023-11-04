# Project Overview

This repository provides detailed information about two distinct projects, each focusing on specific AWS-related tasks and security measures. Please refer to the following sections for a quick overview of each project.

## Project 1: AWS API Real-time Monitoring

Project 1 aims to enhance security and real-time monitoring of key AWS activities. It focuses on monitoring AWS operations performed via APIs and auditing corresponding CloudTrail logs. The project includes the following key components:

- **Monitoring Flowchart**: Visual representation of the monitoring process.
- **Monitoring Description**: An explanation of how monitoring works, including the flow of logs from AWS services to CloudWatch and Lambda.
- **Monitored Targets**: A list of AWS events and actions monitored, including security group configuration changes and KMS key actions.
- **CloudWatch Events**: Details about CloudWatch Events for specific event patterns.
- **Lambda Source Code**: Access to the Lambda functions used for forwarding audit-related events.

For installation and configuration instructions, please refer to the [API-Monitor Guide.md](AWS-API-Monitor/README.md).

## Project 2: Amazon Systems Manager (SSM) Implementation

Project 2 focuses on implementing Amazon Systems Manager (SSM) on AWS for efficient instance management and enhanced security. The project includes the following key components:

- **Overview**: An introduction to the purpose and goals of implementing Amazon SSM.
- **Background Knowledge**: Prerequisite knowledge required for implementing SSM, including AWS infrastructure, IAM roles, KMS encryption, and CloudTrail usage.
- **Usage Plans**: A detailed plan for installing the Amazon SSM agent on AWS instances and ensuring secure and efficient management. This includes recommendations for IAM roles and security policies.
- **Security Measures**: Information about implementing security measures, including Service Control Policies (SCP), session encryption, and session logging and monitoring.

For installation and usage instructions, please refer to the [Lambda for SSM Guide.md](SSM/readme.md).

## Author

This repository is maintained by @twodragon. For questions or further assistance, please reach out to the author.

