Credential Audit Tool
Tent and Table Studio
A lightweight, secure, and professional-grade CLI tool for auditing password data.

==========================
FEATURES
==========================
- Analyze credentials from a CSV file
- Detect:
  • Weak passwords (low entropy or common)
  • Reused passwords
  • Pwned passwords (via HaveIBeenPwned API)
- Entropy-based strength scoring (0–100)
- CSV report export
- Terminal color coding
- Supports Windows-style file paths (no escaping required)

==========================
INPUT FORMAT
==========================
Your input should be a .csv file with no headers, and each line like this:

email@example.com,password123
anotheruser@site.com,SecurePass!2024

==========================
HOW TO RUN
==========================
1. Install Python 3
   Download from: https://www.python.org/downloads/

2. Install dependencies:
   pip install colorama requests

3. Run the script:
   python audit.py

When prompted:
Enter path to CSV (email,password):
Use a valid file path, like:
C:\Users\YourName\Desktop\my_credentials.csv

==========================
OUTPUT
==========================
The terminal will show:
- Entropy score (0–100)
- Security flags: Weak, Reused, Pwned
- Audit summary

You'll then be asked if you'd like to export the results:
Output file: tent_and_table_audit_report.csv

==========================
CUSTOMIZATION
==========================
- Add to the COMMON_PASSWORDS set in audit.py to expand the weak list.
- Modify calculate_entropy() to change strength rules.
- Want a GUI version? You can build on this foundation.

==========================
DISCLAIMER
==========================
This tool is for educational and internal auditing purposes only.
Do not use it on credentials you do not own or have permission to analyze.


==========================
GUI VERSION
==========================
We also provide a GUI version: `audit_gui.py`

HOW TO USE:
1. Install Python 3 if not already installed.
2. Install the required package:
   pip install requests
   (tkinter is built into Python on Windows)

3. Run the GUI:
   python audit_gui.py

You’ll get a graphical interface that lets you:
- Load CSV files via file picker
- Choose to enable or disable pwned password checks
- View results in a table with entropy and security flags
- Export results to a CSV file


==========================
LICENSE
==========================
MIT License – use freely, modify, contribute.

Created by Tent and Table Studio

Proverbs 10:9 (NIV)
Whoever walks in integrity walks securely,
but whoever takes crooked paths will be found out.
