from flask import Flask, request, redirect, session, render_template_string
from flask_bcrypt import Bcrypt
import sqlite3
import re
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(32))
bcrypt = Bcrypt(app)

def get_db():
    conn = sqlite3.connect("users.db")
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)")
    return conn

page = """
<h1>Secure Login System</h1>
<h2>{{ title }}</h2>
<p style="color:green">{{ message }}</p>
<form method="POST">
<input name="username" placeholder="Username" required minlength="3" maxlength="30">
<br><br>
<input name="password" type="password" placeholder="Password" required minlength="8" maxlength="128">
<br><br>
<button type="submit">{{ title }}</button>
</form>
<p><a href="/register">Register</a> | <a href="/login">Login</a> | <a href="/dashboard">Dashboard</a> | <a href="/logout">Logout</a></p>
"""

@app.route("/")
def home():
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            message = "Username must be 3-30 letters, numbers, or underscores."
        elif len(password) < 8 or len(password) > 128:
            message = "Password must be 8-128 characters."
        else:
            hashed = bcrypt.generate_password_hash(password).decode("utf-8")
            conn = get_db()
            try:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
                conn.commit()
                message = "Registration successful! You can now log in."
            except sqlite3.IntegrityError:
                message = "Username already exists."
            finally:
                conn.close()
    return render_template_string(page, title="Register", message=message)

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT username, password FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user[1], password):
            session.clear()
            session["username"] = user[0]
            return redirect("/dashboard")
        message = "Invalid username or password."
    return render_template_string(page, title="Login", message=message)

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect("/login")
    return "<h1>Welcome, " + session["username"] + "!</h1><p>You are logged in.</p><a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    get_db().close()
    app.run(debug=False)