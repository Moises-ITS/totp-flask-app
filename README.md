# totp-flask-app
Secure Flask app implementing TOTP-based 2FA using bcrypt, Fernet, and pyotp.

# 🔐 TOTP Two-Factor Authentication Web App

A secure web application built with **Flask (Python)** that implements **Time-Based One-Time Password (TOTP)** authentication — the same standard used by Google Authenticator, Authy, and Microsoft Authenticator.

---

## 🚀 Features

- **User Registration & Login**
  - Secure password hashing with `bcrypt`
  - Password complexity enforcement (uppercase, lowercase, number, symbol, 12+ characters)
- **Two-Factor Authentication (2FA)**
  - Generates and encrypts user-specific TOTP secrets using `Fernet` encryption
  - Creates scannable **QR codes** for easy setup in authenticator apps
  - Verifies time-based tokens entered by users
- **Session Management**
  - Uses Flask’s session system to store user data securely
- **Modern UI**
  - Built with Bootstrap for a clean, mobile-friendly interface
  - Includes dedicated pages for registration, login, QR code display, token verification, and dashboard

---

## 🧠 Tech Stack

| Layer | Tools / Libraries |
|-------|--------------------|
| **Backend** | Flask, Python |
| **Security** | bcrypt, cryptography (Fernet), pyotp |
| **Frontend** | HTML, Bootstrap, Jinja2 Templates |
| **Other** | qrcode, JSON (local data storage) |

---

## 🖼️ App Flow

1. **Register** an account → password is hashed and TOTP secret encrypted.  
2. **Scan QR code** with Google Authenticator (or similar).  
3. **Login** using username and password.  
4. **Enter TOTP code** from your authenticator to verify your identity.  
5. **Access Dashboard** → view QR or test token verification.

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/Moises-ITS/totp-flask-app.git
cd totp-flask-app
