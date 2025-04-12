import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# --------------------- Session States ---------------------
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "Home"
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = 0

# --------------------- Utility Functions ---------------------
def hash_passkey(passkey):
    return hashlib.sha3_256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]["passkey"] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_data_id():
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page

# --------------------- App Layout Styling ---------------------
st.set_page_config(page_title="🔐 Secure Data System", page_icon="🔐", layout="centered")

# Adding CSS for better UI
st.markdown("""
    <style>
        .title-text {
            font-size: 36px;
            font-weight: bold;
            text-align: center;
            color: #6c63ff;
            padding: 20px 0;
        }
        .subheader {
            font-size: 28px;
            font-weight: bold;
            margin-top: 10px;
            color: #444;
        }
        .footer {
            text-align: center;
            font-size: 14px;
            color: gray;
            margin-top: 40px;
        }
        .stTextInput > div > input {
            border-radius: 12px;
            padding: 10px;
            font-size: 16px;
            border: 1px solid #ddd;
        }
        .stButton > button {
            background-color: #6c63ff;
            color: white;
            font-size: 18px;
            font-weight: bold;
            padding: 12px 24px;
            border-radius: 10px;
            border: none;
            transition: background-color 0.3s ease;
        }
        .stButton > button:hover {
            background-color: #5a53e6;
        }
        .stTextArea > div > textarea {
            border-radius: 12px;
            padding: 12px;
            font-size: 16px;
            border: 1px solid #ddd;
        }
        .stSidebar {
            background-color: #f4f7ff;
        }
        .stRadio > div > label {
            font-size: 20px;
            color: #444;
            padding: 10px 0;
        }
        .stSuccess {
            background-color: #d4edda;
            border-color: #c3e6cb;
        }
        .stError {
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }
        .stWarning {
            background-color: #fff3cd;
            border-color: #ffeeba;
        }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="title-text">🔐 Secure Data Encryption System</div>', unsafe_allow_html=True)

menu = ["🏠 Home", "📝 Store Data", "🔍 Retrieve Data", "🔑 Login"]

# Set the correct index for the radio button based on the current page
if st.session_state.current_page == "Home":
    index = menu.index("🏠 Home")
elif st.session_state.current_page == "Store Data":
    index = menu.index("📝 Store Data")
elif st.session_state.current_page == "Retrieve Data":
    index = menu.index("🔍 Retrieve Data")
else:
    index = menu.index("🔑 Login")

choice = st.sidebar.radio("📂 Navigation", menu, index=index)

st.session_state.current_page = choice.split(" ", 1)[1]

if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("🚨 Too many failed attempts! Reauthorization required.")

# --------------------- Home ---------------------
if st.session_state.current_page == "Home":
    st.markdown("### 🚀 Welcome to the Secure Data System")
    st.success("Use this app to **securely store** and **retrieve confidential data** using unique passkeys.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("📝 Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("🔍 Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")

    st.info(f"📦 Currently storing **{len(st.session_state.stored_data)}** encrypted data entries.")

# --------------------- Store ---------------------
elif st.session_state.current_page == "Store Data":
    st.markdown("### 📝 Store Data Securely")
    user_data = st.text_area("📄 Enter your confidential data below:")
    passkey = st.text_input("🔑 Create a secure passkey", type="password")
    confirm_passkey = st.text_input("✅ Confirm your passkey", type="password")

    if st.button("🔐 Encrypt & Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("❗ Passkeys do not match!")
            else:
                data_id = generate_data_id()
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.success("✅ Your data has been encrypted and saved securely!")
                st.code(data_id, language="text")
                st.info("💾 Save this **Data ID** for future access.")
        else:
            st.error("⚠️ All fields are required!")

# --------------------- Retrieve ---------------------
elif st.session_state.current_page == "Retrieve Data":
    st.markdown("### 🔍 Retrieve Your Stored Data")
    attempts_remaining = 3 - st.session_state.failed_attempts
    st.warning(f"🧠 Attempts Remaining: {attempts_remaining}")

    data_id = st.text_input("🆔 Enter Data ID:")
    passkey = st.text_input("🔐 Enter Passkey:", type="password")

    if st.button("🔓 Decrypt Data"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                if decrypted_text:
                    st.success("🎉 Decryption successful!")
                    st.markdown("#### 🔓 Decrypted Message:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"🚫 Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("📛 Data ID not found!")

            if st.session_state.failed_attempts >= 3:
                st.warning("🔐 Too many failed attempts! Redirecting to Login Page...")
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error("⚠️ Please fill in both fields.")

# --------------------- Login ---------------------
elif st.session_state.current_page == "Login":
    st.markdown("### 🔐 Admin Login")
    if time.time() - st.session_state.last_attempt_time < 10:
        remaining_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"⏳ Wait {remaining_time} seconds before trying again.")
    else:
        login_pass = st.text_input("🛡️ Enter Master Password:", type="password")
        if st.button("🔑 Login"):
            if login_pass == "admin123":
                reset_failed_attempts()
                st.success("✅ Reauthorized successfully!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect password!")

# --------------------- Footer ---------------------
st.markdown('<div class="footer">🔐 Secure Data Encryption System | Made with ❤️ using Streamlit</div>', unsafe_allow_html=True)
