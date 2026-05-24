"""Intentionally insecure code to exercise the scanner's rules.

This file is part of the demo sample-project. Do NOT copy these patterns.
"""

import hashlib
import pickle

import requests


def hash_password(password):
    # Weak hash used in a security context (Weak Cryptography).
    return hashlib.md5(password.encode()).hexdigest()


def load_session(blob):
    # Unsafe deserialization of untrusted data (Insecure Deserialization).
    return pickle.loads(blob)


def fetch(url):
    # TLS verification disabled (Disabled TLS Verification).
    return requests.get(url, verify=False)


def get_user(cursor, user_id):
    # SQL built via string concatenation (SQL Injection Risk).
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


def login(username, password):
    # Secret written to logs (Sensitive Data in Logs).
    print("Logging in", username, "with password", password)


SERVICE_URL = "http://internal.corp/api/v1"  # Insecure HTTP URL (real host).
