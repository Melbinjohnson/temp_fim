# 🛡️ File Integrity Monitoring (FIM) System

This project is a simple CLI-based File Integrity Monitoring system built with Python. It tracks changes in files within a specified directory by comparing their hashes, sizes, and metadata against a previously recorded baseline.

---

## 📁 Project Structure

```text
fim_project/
├── .env                         # Environment variables (e.g., email credentials)
├── config/
│   └── settings.json            # Core configuration (scan path, interval, alert settings)
├── data/
│   ├── baseline.json            # Baseline snapshot of file hashes and metadata
│   └── report.json              # Latest scan report (changes detected)
├── utils/
│   ├── file_utils.py            # Functions for hashing and file metadata extraction
│   └── email_alert.py           # Sends email alerts; loads credentials from .env
├── initialize.py                # Script to create the initial baseline
├── monitor.py                   # Script to detect file changes by comparing with baseline
```

## 📦 Installation
# 1. Clone the repository
```text
git clone https://github.com/your-username/fim_project.git](https://github.com/Melbinjohnson/fim_project.git
cd fim_project
```

# 2. Create a virtual environment (recommended)
```text
python -m venv fim
source fim/bin/activate       # On Windows: fim\Scripts\activate
```

# 3. Install required dependencies
```text
pip install -r requirements.txt
```

# 4. Create a .env file in the root directory
```text
echo "EMAIL_SENDER=your-email@gmail.com
EMAIL_RECEIVER=receiver@example.com
EMAIL_PASSWORD=your-app-password
EMAIL_SUBJECT=\"FIM Alert - File Changes Detected\"
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
USE_TLS=True" > .env
```

# 5. [Linux only] Install 'aplay' (for beep/alert support)
```text
sudo apt update
sudo apt install alsa-utils
```
