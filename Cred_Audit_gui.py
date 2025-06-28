import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
import hashlib
import math
import requests
from collections import Counter
import os

COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "qwerty",
    "abc123", "111111", "1234567", "password1", "12345",
    "letmein", "admin", "welcome", "iloveyou", "monkey"
}

def calculate_entropy(password):
    if not password:
        return 0
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password): pool += 32
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
        report.append((email, password, entropy, ", ".join(issues or ["OK"])))
    return report

def export_to_csv(data):
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not path:
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Email", "Password", "Entropy", "Issues"])
        writer.writerows(data)
    messagebox.showinfo("Export Successful", f"Report saved to:\n{path}")

def run_audit():
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return

    check_pwned = pwned_var.get()
    try:
        credentials = load_credentials(file_path)
        report = analyze_credentials(credentials, check_pwned=check_pwned)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze credentials:\n{str(e)}")
        return

    for row in tree.get_children():
        tree.delete(row)
    for email, password, entropy, issues in report:
        tree.insert("", "end", values=(email, password, entropy, issues))

    export_btn.config(state=tk.NORMAL)

def tree_data():
    return [tree.item(child)["values"] for child in tree.get_children()]

root = tk.Tk()
root.title("Tent and Table Studio - Credential Audit Tool")
root.geometry("800x500")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="Credential Audit Tool", font=("Helvetica", 16)).pack(pady=10)

btn_frame = ttk.Frame(frame)
btn_frame.pack(fill=tk.X)

pwned_var = tk.BooleanVar(value=True)
ttk.Checkbutton(btn_frame, text="Check HaveIBeenPwned API", variable=pwned_var).pack(side=tk.LEFT)

ttk.Button(btn_frame, text="Load CSV and Audit", command=run_audit).pack(side=tk.LEFT, padx=5)

export_btn = ttk.Button(btn_frame, text="Export Report", command=lambda: export_to_csv(tree_data()), state=tk.DISABLED)
export_btn.pack(side=tk.RIGHT)

tree = ttk.Treeview(frame, columns=("Email", "Password", "Entropy", "Issues"), show="headings")
tree.heading("Email", text="Email")
tree.heading("Password", text="Password")
tree.heading("Entropy", text="Entropy")
tree.heading("Issues", text="Issues")
tree.pack(fill=tk.BOTH, expand=True, pady=10)

root.mainloop()
