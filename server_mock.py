import sqlite3
import os
from flask import Flask, request

app = Flask(__name__)

# MOCK VULNERABILITY 1: SQL Injection (CVE-2024-MOCK-SQL)
@app.route("/user-details")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # DANGER: Directly injecting user input into a string
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return str(cursor.fetchone())

# MOCK VULNERABILITY 2: Path Traversal (CVE-2024-MOCK-PATH)
@app.route("/read-log")
def read_log():
    filename = request.args.get("file")
    
    # DANGER: No validation on the filename allows ../../etc/passwd
    log_path = os.path.join("logs", filename)
    with open(log_path, "r") as f:
        return f.read()

if __name__ == "__main__":
    app.run()