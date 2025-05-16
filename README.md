# Cloud IAM Threat Monitoring System

A Python-based AWS IAM monitoring tool that detects:

- Inactive IAM users for 30+ days
- Roles with newly attached AdministratorAccess policies
- Roles with wildcard ("*:*") permissions — a key privilege escalation risk

It sends alerts via Amazon SNS and generates CSV reports for auditing.

---

## Features

- Identifies IAM users inactive beyond a set threshold
- Detects roles with newly attached admin-level permissions
- Flags roles with wildcard permissions ("*:*") often tied to privilege escalation
- Sends real-time alerts via AWS SNS
- Generates CSV reports for audit and review

---

## Setup

1. Configure your AWS credentials with:
   ```bash
   aws configure
