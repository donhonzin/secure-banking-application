# Secure Banking Application
#Made by Jan Kriz (L00177206)

This project is a Python-based secure banking system that allows users to register, login with Two-Factor Authentication (2FA) and perform secure transactions such as deposits and withdrawals. It follows secure coding practices, input validation, password hashing and activity logging.

---

# Features

- Secure user registration with strong password enforcement
- Secure login with Two-Factor Authentication (QR code & Authenticator app)
- Create checking or savings accounts
- Deposit and withdraw money securely
- View account balance and transaction history
- SQL Injection prevention (using parameterized queries)
- Secure activity logging (activity.log)
- Static code analysis with Bandit (no vulnerabilities found)

---

# Requirements

- Python 3.11 or higher
- Packages:
  - bcrypt
  - pyotp
  - qrcode
  - sqlite3 (standard in Python)
  - bandit (for static code analysis)

# Install required packages:

pip install bcrypt pyotp qrcode bandit
