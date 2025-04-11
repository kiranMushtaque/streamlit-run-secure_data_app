
import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# === CONFIG ===
SALT = b"top_secret_salt"
MAX_ATTEMPTS = 3
MASTER_PASSWORD = "admin123"

# === SESSION STATE INIT ===
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False
if "data_store" not in st.session_state:
    st.session_state.data_store = {}

# === FUNCTIONS ===
def derive_key(passkey: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def encrypt_data(plain_text: str, passkey: str) -> str:
    key = derive_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str | None:
    try:
        key = derive_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# === STREAMLIT UI ===
st.set_page_config(page_title="Secure Encryptor", page_icon="🔐", layout="centered")

# Header Title
st.title("🔒 Secure Data Encryption System")

# === Navigation Menu ===
menu = ["🏠 Home", "📝 Store Data", "🔍 Retrieve Data", "🔑 Login"]
page = st.sidebar.radio("📂 Navigate", menu)

# === Pages ===
if page == "🏠 Home":
    st.subheader("Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")


elif page == "📝 Store Data":
    st.subheader("📝 Store Encrypted Data")
    label = st.text_input("Enter a unique label:")
    data = st.text_area("Enter the sensitive data to store:")
    passkey = st.text_input("Create a strong passkey:", type="password")

    if st.button("Encrypt & Save"):
        if not all([label, data, passkey]):
            st.warning("All fields are required!")
        elif label in st.session_state.data_store:
            st.error("Label already exists. Choose a new one.")
        else:
            encrypted = encrypt_data(data, passkey)
            st.session_state.data_store[label] = encrypted
            st.success(f"✅ Data under label `{label}` has been securely stored!")

elif page == "🔍 Retrieve Data":
    if st.session_state.failed_attempts >= MAX_ATTEMPTS and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts. Please login again.")
        st.stop()

    st.subheader("🔍 Retrieve Your Data")
    if not st.session_state.data_store:
        st.info("ℹ️ No data stored yet.")
    else:
        label = st.selectbox("Select a label:", list(st.session_state.data_store.keys()))
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if not passkey:
                st.warning("⚠️ Please enter your passkey.")
            else:
                encrypted = st.session_state.data_store.get(label)
                decrypted = decrypt_data(encrypted, passkey)

                if decrypted:
                    st.success("✅ Data decrypted successfully!")
                    st.code(decrypted, language="text")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                    if attempts_left == 0:
                        st.warning("🔒 Too many failed attempts. Redirecting to login page...")
                        st.experimental_rerun()

elif page == "🔑 Login":
    st.subheader("🔑 Reauthorization Required")
    master = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master == MASTER_PASSWORD:
            st.session_state.reauthorized = True
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized. You can now decrypt data again.")
        else:
            st.error("❌ Incorrect master password.")
