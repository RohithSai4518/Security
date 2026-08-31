# SecureShare & PySecSuite - Security Operations & File Vault Platform

A complete, enterprise-grade security engineering project and web application built in Python and Django. Features a secure file sharing portal with Role-Based Access Control (RBAC), Anti-IDOR protection, and a modular Security & Threat Analysis Suite with real-time intrusion detection, CVE intelligence, and compliance evaluation.

---

## Dependencies

- **Language:** Python 3.10+
- **Core Framework:** Django 5.1+
- **Manifest:** `requirements.txt`, `pyproject.toml`
- **Lockfile:** `poetry.lock`

---

## Installation

### 1. Clone or Extract the Repository
```bash
cd E:\Security
```

### 2. Set Up Virtual Environment (Recommended)
```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```
*Or using Poetry:*
```bash
poetry install
```

---

## Build

### 1. Apply Database Migrations
```bash
python manage.py migrate
```

### 2. Seed Default Demo Accounts & Files
```bash
python seed_demo_data.py
```

### 3. Build & Verify Security Dictionaries (Optional)
```bash
python build_security_definitions.py
```

---

## Run

### 1. Start the SecureShare Web Portal
```bash
python manage.py runserver 127.0.0.1:8000
```
Open your browser and navigate to: **[http://127.0.0.1:8000/](http://127.0.0.1:8000/)**

### 2. Run CLI Security Scanner & IDS
```bash
# Analyze access logs for intrusions:
python main.py ids sample_attack_log.txt --export

# Run network port scanner:
python main.py scan 127.0.0.1 --ports 22,80,443,8080 --export

# Generate high-entropy password:
python main.py crypto genpass --length 24
```

---

## Usage & Access Credentials

### Pre-Configured Accounts:
- **Security Admin:** `admin` / `AdminPassword@2026`
- **User Alice:** `alice` / `AlicePassword@2026`
- **User Bob:** `bob` / `BobPassword@2026`

### Key Capabilities:
- **Secure File Storage:** Uploaded files are isolated, renamed to UUIDs, and blocked from unauthorized access.
- **Granular Sharing:** Share files with specific usernames and set custom permissions (View Metadata vs. Full Download).
- **Anti-IDOR Enforcement:** Any tampering with file UUIDs results in `403 Forbidden` and gets logged in the security audit trail.
- **Admin Console:** Real-time monitoring of all active files, accounts, and security incident alerts.

---

## Testing

Run all unit and integration tests using Django test runner:
```bash
python manage.py test
```

Run PySecSuite core toolkit unit tests:
```bash
python -m unittest discover -s tests -p "test_*.py"
```
