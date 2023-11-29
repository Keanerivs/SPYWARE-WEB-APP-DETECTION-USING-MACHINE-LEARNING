import streamlit as st

def login():
    st.title("Login Page")

    # Input fields for username and password
    username = st.text_input("Username:")
    password = st.text_input("Password:", type="password")

    # Login button
    if st.button("Login"):
        # Replace this with your actual authentication logic
        if validate_credentials(username, password):
            return True, username
        else:
            st.warning("Invalid credentials. Please try again.")

    return False, None

def validate_credentials(username, password):
    # Replace this with your actual validation logic
    # For simplicity, the function returns True if username and password are not empty
    return bool(username) and bool(password)
