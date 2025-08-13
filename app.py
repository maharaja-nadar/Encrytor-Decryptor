from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change this in production

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Load encryption key
with open('secret.key', 'rb') as key_file:
    key = key_file.read()

fernet = Fernet(key)

# --- Database setup ---
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )""")
    conn.commit()
    conn.close()

init_db()

# --- Routes ---

@app.route('/')
def home():
    if "user" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Password validation (server-side)
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$'
        if not re.match(pattern, password):
            flash("Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 symbol.")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        result = c.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            session["user"] = username
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop("user", None)
    flash("Logged out successfully.")
    return redirect(url_for('login'))

@app.route('/index')
def index():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template('index.html', user=session["user"])

@app.route('/upload', methods=['POST'])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    file = request.files['file']
    action = request.form['action']

    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            data = f.read()

        if action == 'encrypt':
            processed = fernet.encrypt(data)
            new_filename = file.filename + '.encrypted'
        elif action == 'decrypt':
            processed = fernet.decrypt(data)
            new_filename = file.filename.replace('.encrypted', '') + '.decrypted'
        else:
            return "Invalid action"

        processed_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        with open(processed_path, 'wb') as f:
            f.write(processed)

        return send_file(processed_path, as_attachment=True)

    return "No file uploaded"

if __name__ == '__main__':
    app.run(debug=True)
