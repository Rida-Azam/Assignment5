# 🔐 Secure Data Encryption System

A simple yet secure web-based application built using **Streamlit** to encrypt and store confidential data, and retrieve it using a unique **Data ID** and **passkey**. The system includes features like encryption, decryption, brute-force protection, and an admin login for reauthorization.

---

## 🌟 Features

- 📝 **Secure Data Storage** – Store encrypted text securely with a passkey.
- 🔍 **Data Retrieval** – Retrieve data using your unique Data ID and passkey.
- 🔒 **Passkey Hashing** – Passkeys are hashed using SHA-3 for added security.
- 🔐 **Fernet Encryption** – AES-based symmetric encryption ensures confidentiality.
- 🛡️ **Brute Force Protection** – Lockout after 3 failed attempts.
- 🔑 **Admin Login** – Reauthorization via master password after multiple failures.
- 🎨 **Custom UI** – Stylish, interactive, and responsive Streamlit UI.

---

## 🚀 Demo

![App Screenshot](https://via.placeholder.com/600x300?text=Secure+Data+System+Screenshot)

---

## 🔧 Installation

1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/secure-data-encryption.git
cd secure-data-encryption
