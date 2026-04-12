import sqlite3
import os
import hashlib
import pickle
import requests
import yaml
from flask import Flask, redirect, request
from django.views.decorators.csrf import csrf_exempt

# py/no-hardcoded-secret
password = "supersecret123"

# py/django-secret-key-hardcoded
SECRET_KEY = "my-super-secret-django-key"

# py/flask-secret-key-hardcoded
app = Flask(__name__)
app.secret_key = "my-hardcoded-flask-secret"

# py/session-cookie-secure-disabled
SESSION_COOKIE_SECURE = False

# py/session-cookie-httponly-disabled
SESSION_COOKIE_HTTPONLY = False

# py/session-cookie-samesite-disabled
SESSION_COOKIE_SAMESITE = "None"

# py/csrf-cookie-secure-disabled
CSRF_COOKIE_SECURE = False

# py/csrf-cookie-httponly-disabled
CSRF_COOKIE_HTTPONLY = False

# py/csrf-cookie-samesite-disabled
CSRF_COOKIE_SAMESITE = "None"

# py/csrf-exempt
@csrf_exempt
def webhook(request):
    return "ok"

# py/wtf-csrf-disabled
WTF_CSRF_ENABLED = False

# py/wtf-csrf-check-default-disabled
WTF_CSRF_CHECK_DEFAULT = False

# py/django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["*"]

# py/secure-ssl-redirect-disabled
SECURE_SSL_REDIRECT = False

# py/no-ssrf
requests.get(request.args["url"])

# py/no-path-traversal
os.remove(user_path)

# py/no-sql-injection (string concat with cursor.execute)
def run_query(user_input):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user_input)
    return cursor.fetchall()

# py/no-eval
def dangerous():
    eval(input("Enter code: "))
    exec("print('hello')")

# py/no-command-injection
def run_cmd(user_input):
    os.system(user_input)

# py/no-path-traversal
def read_file(user_path):
    f = open(user_path)
    return f.read()

# py/no-weak-crypto
def weak_hash(data):
    return hashlib.md5(data)

# py/no-pickle
def deserialize(data):
    return pickle.loads(data)

# py/no-yaml-load
def parse_yaml(data):
    return yaml.load(data)

# py/no-debug-true
DEBUG = True

# py/no-open-redirect
def do_redirect(url):
    return redirect(url)

# py/no-cors-star
CORS_ALLOW_ALL_ORIGINS = True

# py/flask-debug-mode
app.run(debug=True)

# py/jwt-no-verify
import jwt
decoded = jwt.decode(token, "secret", options={"verify_signature": False})

# py/jwt-hardcoded-secret
token = jwt.encode(payload, "my-hardcoded-jwt-secret", algorithm="HS256")
