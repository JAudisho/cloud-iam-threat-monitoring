# Cloud IAM Threat Monitoring System

A Python-based AWS IAM monitoring tool that detects:
- Inactive IAM users for 30+ days
- New roles attached to AdministratorAccess policies

It sends alerts via Amazon SNS and generates a CSV report.

## Features

- ✅ Identifies IAM users inactive beyond a set threshold
- ✅ Detects roles with newly attached admin-level permissions
- ✅ Sends real-time alerts via SNS
- ✅ Generates easy-to-read CSV reports for audit use

## Setup

1. Configure your AWS credentials with:
   ```bash
   aws configure