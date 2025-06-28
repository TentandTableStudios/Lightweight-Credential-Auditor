import csv
import hashlib
import math
import requests
from collections import Counter
from colorama import Fore, Style, init
import os

init(autoreset=True)

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "qwerty",
    "abc123", "111111", "1234567", "password1", "12345",
    "letmein", "admin", "welcome", "iloveyou", "monkey"
}

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def calculate_entropy(password):
    if not password:
        return 0
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
        pool += 32
    entropy = len(password) * math.log2(pool) if pool else 0
    return round(min(entropy, 100), 2)

def is_common_password(password):
    return password.lower() in COMMON_PASSWORDS

def is_password_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200:
        return False
    hashes = (line.split(':') for line in res.text.splitlines())
    return any(h == suffix for h, _ in hashes)

def load_credentials(file_path):
    credentials = []
    with open(file_path, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                credentials.append((row[0].strip(), row[1].strip()))
    return credentials

def analyze_credentials(credentials, check_pwned=True):
    report = []
    password_counter = Counter(pw for _, pw in credentials)

    for email, password in credentials:
        entropy = calculate_entropy(password)
        issues = []
        if password_counter[password] > 1:
            issues.append("Reused")
        if is_common_password(password) or entropy < 40:
            issues.append("Weak")
        if check_pwned:
            try:
                if is_password_pwned(password):
                    issues.append("Pwned")
            except:
                issues.append("PwnedCheckFailed")
        report.append({
            "email": email,
            "password": password,
            "entropy": entropy,
            "issues": issues or ["OK"]
        })
    return report

def print_report(report):
    weak, reused, pwned = 0, 0, 0
    print("\nAudit Report:")
    for entry in report:
        color = Fore.GREEN
        if any(issue in entry['issues'] for issue in ["Weak", "Reused", "Pwned"]):
            color = Fore.RED
        if "OK" in entry['issues']:
            color = Fore.CYAN

        print(f"{color}[✔] {entry['email']:<30} | Entropy: {entry['entropy']:<5} | Issues: {', '.join(entry['issues'])}")

        weak += "Weak" in entry['issues']
        reused += "Reused" in entry['issues']
        pwned += "Pwned" in entry['issues']

    print(Style.BRIGHT + "\nSummary:")
    print(f" ├── Total Accounts: {len(report)}")
    print(f" ├── Weak Passwords: {weak}")
    print(f" ├── Reused Passwords: {reused}")
    print(f" └── Pwned Passwords: {pwned}")

def export_report(report, filename="tent_and_table_audit_report.csv"):
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Email", "Password", "Entropy", "Issues"])
        for entry in report:
            writer.writerow([entry['email'], entry['password'], entry['entropy'], '; '.join(entry['issues'])])
    print(Fore.YELLOW + f"\nReport exported to {filename}")

def main():
    clear_screen()
    print(Style.BRIGHT + Fore.CYAN + "╔════════════════════════════════════════════════════════════════╗")
    print(Fore.CYAN + "║  Tent and Table Studio - Credential Audit Tool v1.0           ║")
    print(Fore.CYAN + "╚════════════════════════════════════════════════════════════════╝\n")

    raw_path = input("Enter path to CSV (email,password): ").strip()
    path = os.path.normpath(raw_path)

    if not os.path.exists(path):
        print(Fore.RED + "File not found.")
        return

    choice = input("Check for pwned passwords via API? (Y/n): ").strip().lower()
    check_pwned = choice != 'n'

    credentials = load_credentials(path)
    report = analyze_credentials(credentials, check_pwned=check_pwned)
    print_report(report)

    if input("\nExport report to CSV? (Y/n): ").strip().lower() != 'n':
        export_report(report)

if __name__ == "__main__":
    main()
