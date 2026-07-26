# Sample Vulnerable Python Application for Testing Task 3
import os
import hashlib
import pickle

# Vulnerability 1: Hardcoded AWS API Secret Key
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE_SECRET_KEY_HERE"
DB_PASSWORD = "SuperSecretAdminPassword123!"

def login_user(username, user_input_pass):
    # Vulnerability 2: Weak MD5 Hash for password
    hashed_pass = hashlib.md5(user_input_pass.encode()).hexdigest()
    
    # Vulnerability 3: SQL Injection vulnerability via string formatting
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashed_pass + "'"
    print(f"Executing query: {query}")

def execute_user_command(user_cmd):
    # Vulnerability 4: Dangerous OS Command Injection
    os.system("ping -c 1 " + user_cmd)

def load_user_session(session_data):
    # Vulnerability 5: Insecure Deserialization & Code Evaluation
    session = pickle.loads(session_data)
    eval("print('Loaded session')")
    return session
