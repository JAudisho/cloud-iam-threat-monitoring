import boto3
from datetime import datetime, timezone, timedelta
import yaml
from utils import send_alert
from report_generator import generate_report

# Load config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

iam = boto3.client("iam")
sns = boto3.client("sns")

def get_inactive_users(threshold_days):
    response = iam.generate_credential_report()
    report = iam.get_credential_report()["Content"].decode("utf-8").splitlines()
    headers = report[0].split(",")
    users = [line.split(",") for line in report[1:]]

    inactive = []
    for user in users:
        user_data = dict(zip(headers, user))
        last_used = user_data.get("password_last_used") or user_data.get("access_key_1_last_used_date")
        if last_used == "N/A":
            continue
        try:
            last_used_date = datetime.strptime(last_used, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - last_used_date > timedelta(days=threshold_days):
                inactive.append(user_data["user"])
        except ValueError:
            continue

    return inactive

def get_new_admin_roles():
    paginator = iam.get_paginator('list_roles')
    roles = []
    for page in paginator.paginate():
        for role in page['Roles']:
            attached = iam.list_attached_role_policies(RoleName=role['RoleName'])
            for policy in attached['AttachedPolicies']:
                if "AdministratorAccess" in policy['PolicyName']:
                    roles.append(role['RoleName'])
    return roles

def detect_wildcard_permissions():
    roles = iam.list_roles()['Roles']
    risky_roles = []

    for role in roles:
        try:
            policies = iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
            for policy in policies:
                version = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                document = iam.get_policy_version(
                    PolicyArn=policy['PolicyArn'], VersionId=version
                )['PolicyVersion']['Document']

                statements = document.get("Statement", [])
                if not isinstance(statements, list):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") == "Allow" and stmt.get("Action") == "*" and stmt.get("Resource") == "*":
                        risky_roles.append(role['RoleName'])
        except Exception as e:
            continue  # skip any role with restricted access or malformed policy

    return risky_roles

if __name__ == "__main__":
    inactive_users = get_inactive_users(config["inactive_days_threshold"])
    admin_roles = get_new_admin_roles()
    risky_roles = detect_wildcard_permissions()

    if inactive_users:
        send_alert(f"Inactive Users over {config['inactive_days_threshold']} days: {inactive_users}", config["sns_topic_arn"])
    if admin_roles:
        send_alert(f"Admin Policy Roles Detected: {admin_roles}", config["sns_topic_arn"])
    if risky_roles:
        send_alert(f"Roles with Wildcard Permissions Detected: {risky_roles}", config["sns_topic_arn"])

    generate_report(inactive_users, admin_roles + risky_roles)