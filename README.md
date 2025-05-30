# Cloud IAM Threat Monitoring System

A Python-based monitoring solution that audits AWS IAM configurations to detect security risks such as privilege escalation, inactive users, and root account usage. Alerts are triggered through AWS SNS and logs are collected via CloudWatch for analysis.

## ⚙️ Features

- Audits IAM roles for newly attached admin policies
- Flags inactive users exceeding 30 days of non-usage
- Identifies usage of root accounts and enforces MFA checks
- Triggers alerts through Amazon SNS
- Logs events using CloudWatch for centralized monitoring

## 🧠 Tech Stack

- Python 3.10+
- AWS Boto3 SDK
- AWS IAM, SNS, CloudWatch
- JSON configuration and output formatting

## 🚀 Sample Output

[ALERT] Admin policy attached to IAM role: DevOpsAdminRole
[ALERT] Inactive user detected: intern_user (Last activity: 45 days ago)
[ALERT] Root account activity detected - MFA not enabled
