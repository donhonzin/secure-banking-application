# ==========================================
# ============ SECURE BANKING APP ===========
# ==========================================
# Author: Jan Kriz

import sqlite3
import bcrypt
import pyotp
import qrcode
import datetime
import re

# ==========================================
# =========== LOGGING FUNCTIONS ============
# ==========================================

# Logs activities such as registration, login, transactions
def log_event(event_type, username, details=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("activity.log", "a") as log_file:
        log_file.write(f"[{timestamp}] {event_type} - User: {username} {details}\n")

# ==========================================
# ===== PASSWORD STRENGTH VALIDATION =======
# ==========================================

# Ensures passwords meet security standards
def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\/:{}|]", password):
        return False
    return True

# ==========================================
# =============== DATABASE =================
# ==========================================

# Initializes SQLite database and creates necessary tables
def init_db():
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS USERS (
        USER_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        USERNAME TEXT UNIQUE NOT NULL,
        PASSWORD_HASH TEXT NOT NULL,
        OTP_SECRET TEXT,
        CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ACCOUNTS (
        ACCOUNT_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        USER_ID INTEGER,
        ACCOUNT_TYPE TEXT CHECK (ACCOUNT_TYPE IN ('CHECKING', 'SAVINGS')),
        BALANCE REAL DEFAULT 0 CHECK (BALANCE >= 0),
        CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(USER_ID) REFERENCES USERS(USER_ID)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS TRANSACTIONS (
        TRANSACTION_ID INTEGER PRIMARY KEY AUTOINCREMENT,
        ACCOUNT_ID INTEGER,
        TYPE TEXT CHECK (TYPE IN ('DEPOSIT', 'WITHDRAW')),
        AMOUNT REAL CHECK (AMOUNT > 0),
        TRANSACTION_TIME TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ACCOUNT_ID) REFERENCES ACCOUNTS(ACCOUNT_ID)
    )
    ''')

    conn.commit()
    conn.close()

# ==========================================
# =============== USER FUNCTIONS ===========
# ==========================================

# Registers new users with hashed passwords and 2FA secret generation
def write_user(username, password):
    if not username.strip():
        print("❌ Username cannot be empty.")
        return
    if not password.strip():
        print("❌ Password cannot be empty.")
        return
    if not is_password_strong(password):
        print("❌ Password too weak! Must be 8+ chars, uppercase, lowercase, number, and special char.")
        return

    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    otp_secret = pyotp.random_base32()

    try:
        cursor.execute("INSERT INTO USERS (USERNAME, PASSWORD_HASH, OTP_SECRET) VALUES (?, ?, ?)", (username, password_hash.decode(), otp_secret))
        conn.commit()
        print("✅ User registered successfully!")
        log_event("Registration", username)

        # Generate 2FA QR code
        totp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="Secure Bank")
        qr = qrcode.make(totp_uri)
        qr.save(f"{username}_qr.png")
        print(f"✅ 2FA QR Code saved as {username}_qr.png")

    except sqlite3.IntegrityError:
        print("❌ Username already exists.")

    conn.close()

# Validates login credentials and performs OTP verification
def validate_login(username, password):
    if not username.strip():
        print("❌ Username cannot be empty.")
        return False
    if not password.strip():
        print("❌ Password cannot be empty.")
        return False

    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    cursor.execute("SELECT PASSWORD_HASH, OTP_SECRET FROM USERS WHERE USERNAME = ?", (username,))
    result = cursor.fetchone()

    if not result:
        print("❌ Invalid username.")
        return False

    stored_hash, otp_secret = result
    stored_hash = stored_hash.encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        print("❌ Incorrect password.")
        return False

    otp = input("Enter OTP from your Authenticator App: ")
    totp = pyotp.TOTP(otp_secret)
    if not totp.verify(otp):
        print("❌ Invalid OTP.")
        return False

    print("✅ Login successful!")
    log_event("Login", username)
    return True

# Fetches a user's ID based on username
def get_user_id(username):
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    cursor.execute("SELECT USER_ID FROM USERS WHERE USERNAME = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result[0]
    else:
        return None

# ==========================================
# ============= BANKING FUNCTIONS ==========
# ==========================================

# Banking menu for logged-in users
def banking_menu(user_id, username):
    while True:
        print("\n--- Banking Menu ---")
        print("1. Create new account")
        print("2. View accounts and balances")
        print("3. Deposit money")
        print("4. Withdraw money")
        print("5. Log out")

        choice = input("Choose: ")

        if choice == "1":
            create_account(user_id)
        elif choice == "2":
            view_accounts(user_id)
        elif choice == "3":
            deposit(user_id, username)
        elif choice == "4":
            withdraw(user_id, username)
        elif choice == "5":
            print("👋 Logging out...")
            break
        else:
            print("❌ Invalid choice.")

# Allows users to create a new CHECKING or SAVINGS account
def create_account(user_id):
    account_type = input("Enter account type (CHECKING/SAVINGS): ").upper().strip()
    if account_type not in ["CHECKING", "SAVINGS"]:
        print("❌ Invalid account type.")
        return

    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ACCOUNTS (USER_ID, ACCOUNT_TYPE, BALANCE) VALUES (?, ?, 0)", (user_id, account_type))
    conn.commit()
    conn.close()
    print(f"✅ {account_type} account created.")

# Displays all user's accounts and balances
def view_accounts(user_id):
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ACCOUNT_ID, ACCOUNT_TYPE, BALANCE FROM ACCOUNTS WHERE USER_ID = ?", (user_id,))
    accounts = cursor.fetchall()
    conn.close()

    if accounts:
        print("\n--- Your Accounts ---")
        for acc in accounts:
            print(f"ID: {acc[0]} | Type: {acc[1]} | Balance: €{acc[2]:.2f}")
    else:
        print("❌ No accounts found.")

# Handles deposit functionality
def deposit(user_id, username):
    account_id = input("Enter account ID to deposit into: ")
    try:
        amount = float(input("Enter amount to deposit: "))
    except ValueError:
        print("❌ Invalid amount.")
        return

    if amount <= 0 or amount > 1000000:
        print("❌ Amount must be between €0.01 and €1,000,000.")
        return

    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()

    # Authorization check
    cursor.execute("SELECT 1 FROM ACCOUNTS WHERE ACCOUNT_ID = ? AND USER_ID = ?", (account_id, user_id))
    if not cursor.fetchone():
        print("❌ Unauthorized access.")
        log_event("Unauthorized Deposit", username, f"Account ID {account_id}")
        conn.close()
        return

    cursor.execute("UPDATE ACCOUNTS SET BALANCE = BALANCE + ? WHERE ACCOUNT_ID = ?", (amount, account_id))
    cursor.execute("INSERT INTO TRANSACTIONS (ACCOUNT_ID, TYPE, AMOUNT) VALUES (?, 'DEPOSIT', ?)", (account_id, amount))
    conn.commit()
    conn.close()

    print(f"✅ Deposited ${amount:.2f} successfully!")
    log_event("Deposit", username, f"Deposited €{amount:.2f} into Account ID {account_id}")

# Handles withdrawal functionality
def withdraw(user_id, username):
    account_id = input("Enter account ID to withdraw from: ")
    try:
        amount = float(input("Enter amount to withdraw: "))
    except ValueError:
        print("❌ Invalid amount.")
        return

    if amount <= 0 or amount > 1000000:
        print("❌ Amount must be between €0.01 and €1,000,000.")
        return

    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()

    cursor.execute("SELECT BALANCE FROM ACCOUNTS WHERE ACCOUNT_ID = ? AND USER_ID = ?", (account_id, user_id))
    result = cursor.fetchone()

    if not result:
        print("❌ Unauthorized access.")
        log_event("Unauthorized Withdraw", username, f"Account ID {account_id}")
        conn.close()
        return

    balance = result[0]
    if balance < amount:
        print("❌ Insufficient funds.")
    else:
        cursor.execute("UPDATE ACCOUNTS SET BALANCE = BALANCE - ? WHERE ACCOUNT_ID = ?", (amount, account_id))
        cursor.execute("INSERT INTO TRANSACTIONS (ACCOUNT_ID, TYPE, AMOUNT) VALUES (?, 'WITHDRAW', ?)", (account_id, amount))
        conn.commit()
        print(f"✅ Withdrawn ${amount:.2f} successfully!")
        log_event("Withdraw", username, f"Withdrew ${amount:.2f} from Account ID {account_id}")
    conn.close()

# ==========================================
# =============== ENTRY POINT ==============
# ==========================================

# Starts the application
if __name__ == "__main__":
    init_db()
    while True:
        print("\n--- Welcome to Secure Bank ---")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            username = input("Choose username: ")
            password = input("Choose password: ")
            write_user(username, password)

        elif choice == "2":
            username = input("Username: ")
            password = input("Password: ")
            if validate_login(username, password):
                user_id = get_user_id(username)
                if user_id:
                    banking_menu(user_id, username)
                else:
                    print("❌ Could not retrieve user ID.")

        elif choice == "3":
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid choice.")
