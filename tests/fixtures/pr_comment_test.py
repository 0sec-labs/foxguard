from flask import request
import os
import subprocess

def handler():
    cmd = request.args.get("cmd")
    os.system("ping " + cmd)

def search():
    query = request.args.get("q")
    conn = __import__('sqlite3').connect('db.sqlite')
    conn.execute("SELECT * FROM users WHERE name = '" + query + "'")
