import csv


def load_logs(filename):
    """Read authentication logs from a CSV file."""
    all_logins = []
    failed_logins = []

    with open(filename, "r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            all_logins.append(row)

            if row["status"] == "failed":
                failed_logins.append(row)

    return all_logins, failed_logins


def count_failed_by_user(failed_logins):
    """Count failed login attempts for each username."""
    failed_by_user = {}

    for row in failed_logins:
        username = row["username"]

        if username not in failed_by_user:
            failed_by_user[username] = 0

        failed_by_user[username] += 1

    return failed_by_user


def count_failed_by_ip(failed_logins):
    """Count failed login attempts for each IP address."""
    failed_by_ip = {}

    for row in failed_logins:
        ip_address = row["ip_address"]

        if ip_address not in failed_by_ip:
            failed_by_ip[ip_address] = 0

        failed_by_ip[ip_address] += 1

    return failed_by_ip


def find_suspicious_users(failed_by_user, threshold=3):
    """Identify users with repeated failed login attempts."""
    suspicious_users = {}

    for username, count in failed_by_user.items():
        if count >= threshold:
            suspicious_users[username] = count

    return suspicious_users


def find_suspicious_ips(failed_by_ip, threshold=3):
    """Identify IP addresses with repeated failed login attempts."""
    suspicious_ips = {}

    for ip_address, count in failed_by_ip.items():
        if count >= threshold:
            suspicious_ips[ip_address] = count

    return suspicious_ips


def find_success_after_failures(all_logins, suspicious_ips):
    """Find successful logins from IPs with repeated failures."""
    suspicious_patterns = []

    for ip_address, failed_count in suspicious_ips.items():

        for row in all_logins:

            if row["ip_address"] == ip_address and row["status"] == "success":
                suspicious_patterns.append({
                    "ip_address": ip_address,
                    "failed_attempts": failed_count,
                    "username": row["username"],
                    "timestamp": row["timestamp"]
                })

    return suspicious_patterns


# ------------------------------------------------------------
# Main security analysis
# ------------------------------------------------------------

all_logins, failed_logins = load_logs("login_events.csv")

failed_by_user = count_failed_by_user(failed_logins)
failed_by_ip = count_failed_by_ip(failed_logins)

suspicious_users = find_suspicious_users(failed_by_user)
suspicious_ips = find_suspicious_ips(failed_by_ip)

suspicious_patterns = find_success_after_failures(
    all_logins,
    suspicious_ips
)


# ------------------------------------------------------------
# Security report
# ------------------------------------------------------------

print("=" * 60)
print("PYTHON SECURITY LOG ANALYZER")
print("=" * 60)

print("\nTotal authentication events:", len(all_logins))
print("Total failed login attempts:", len(failed_logins))


print("\n--- Suspicious Users ---")

if suspicious_users:
    for username, count in suspicious_users.items():
        print(
            f"ALERT: {username} - "
            f"{count} failed login attempts"
        )
else:
    print("No suspicious users identified.")


print("\n--- Suspicious IP Addresses ---")

if suspicious_ips:
    for ip_address, count in suspicious_ips.items():
        print(
            f"ALERT: {ip_address} - "
            f"{count} failed login attempts"
        )
else:
    print("No suspicious IP addresses identified.")


print("\n--- Successful Login After Repeated Failures ---")

if suspicious_patterns:
    for event in suspicious_patterns:
        print(
            f"ALERT: {event['ip_address']} had "
            f"{event['failed_attempts']} failed attempts "
            f"followed by a successful login for "
            f"{event['username']} at {event['timestamp']}."
        )
else:
    print("No suspicious login patterns identified.")


print("\nAnalysis complete.")
