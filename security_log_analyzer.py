import csv

failed_logins = []

with open("login_events.csv", "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        if row["status"] == "failed":
            failed_logins.append(row)

print("Total failed login attempts:", len(failed_logins))
