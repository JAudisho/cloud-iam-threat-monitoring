import csv
from datetime import datetime

def generate_report(inactive_users, admin_roles):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    with open(f"iam_report_{timestamp}.csv", "w", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Inactive Users", "Admin Roles with Elevated Access"])
        max_len = max(len(inactive_users), len(admin_roles))
        for i in range(max_len):
            row = [
                inactive_users[i] if i < len(inactive_users) else "",
                admin_roles[i] if i < len(admin_roles) else ""
            ]
            writer.writerow(row)
