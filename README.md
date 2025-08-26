# GPA5 Reception Account Takeover PoC 🚨

[![Python](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/) 
[![License](https://img.shields.io/badge/license-Private-red)](LICENSE) 
[![Status](https://img.shields.io/badge/status-Experimental-orange)]()

**Author:** `Juhin69`  
**Purpose:** Authorized testing of password reset vulnerabilities on GPA5 Reception.

---

## ⚡ Features

- Interactive console with colorful banner 🎨
- Set target phone & new password easily
- Harmless check request before actual exploit
- Exploit execution with confirmation prompt
- Automatic JSON evidence generation & sanitization
- Terminal output with author attribution and highlights

---

## 💻 Installation

```bash
git clone <repo-url>
cd <repo-folder>
pip3 install -r requirements.txt



🚀 Usage

Start the interactive console:

python3 gpa5_PRO.py console


Commands:

set phone <phone-number>        # Set target phone
set password <new-password>     # Set password to reset
show                            # Show current configuration
check                           # Run harmless check
run                             # Execute exploit (requires confirmation)
login <url>                     # Attempt login after exploit
sanitize <file.json>            # Sanitize sensitive info from evidence
exit                            # Exit console


Confirmation Prompt:

Type I_HAVE_PERMISSION (or your modified confirmation phrase) to run destructive actions.

⚠️ Warning

Only use on accounts you own or have explicit permission to test. Unauthorized use is illegal.

📄 License

For educational and authorized penetration testing only. Unauthorized usage prohibited.

📫 Contact

Author: dev.juhin@gmail.com
Reach out via GitHub for questions or contributions.
