import subprocess
import os

def run_command(user_input):
    # Command injection vulnerability
    result = subprocess.call("echo " + user_input, shell=True)
    return result

def read_file(filename):
    # Path traversal vulnerability
    path = "/data/" + filename
    with open(path) as f:
        return f.read()

API_KEY = "AKIA1234567890ABCDEF"
PASSWORD = "supersecretpassword123"
