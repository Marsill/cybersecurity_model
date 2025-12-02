# Cybersecurity Model (Project Two)

This repository implements an access control and authentication model as part of an academic project.

Features implemented:

- Mandatory Access Control (MAC) via sensitivity labels on `User` and checks in decorators
- Discretionary Access Control (DAC) via role/permission assignment and owner-controlled functions (placeholders)
- Role-Based Access Control (RBAC) with `Role` and `Permission` models and `assign-role` endpoint
- Rule-Based Access Control (RuBAC) time-based rule decorator
- Attribute-Based Access Control (ABAC) attributes on `User` model (department, location, employment_status)
- Authentication: registration, login, JWT, password policies, account lockout
- MFA: TOTP (pyotp) support and enable endpoint
- Audit logging: DB `AuditLog` plus encrypted file logging using `cryptography`
- Captcha placeholder endpoint for registration
- Backup utility that encrypts DB copies (demo)

Quick start (Windows PowerShell):

1. Create a virtual environment and install requirements:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Run the app (development):

```powershell
python run.py
```

3. Endpoints:

- `POST /auth/register` - register
- `POST /auth/login` - obtain JWT
- `POST /auth/enable-otp` - enable TOTP for user (JWT required)
- `POST /auth/register-with-captcha` - demo captcha-protected registration

Notes:

- This project includes demo implementations and placeholders. Do not use keys stored in `/instance` in production.
- To run with Postgres, set `DATABASE_URI` environment variable.
