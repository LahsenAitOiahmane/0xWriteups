import sqlite3
from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
import os
import jwt
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv("env.forge")

app = Flask(__name__)
JWT_SECRET = os.environ.get('JWT_SECRET')
ADMIN_PASS = os.environ.get('ADMIN_PASS')
DATABASE = 'insec.db'
PORT = 1337

def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('DROP TABLE IF EXISTS users;')
        db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);')
        
        hashed_admin = generate_password_hash(ADMIN_PASS)
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?);", ('admin', hashed_admin, 'admin'))
        
        if os.path.exists("flag.txt"):
            with open("flag.txt", "r") as f:
                flag = f.read().strip()
                db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?);", ('flag', generate_password_hash(flag), flag))
        db.commit()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/profil')
def profil():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return render_template('profil.html', user=decoded)
    except jwt.InvalidTokenError:
        return redirect(url_for('login'))
    
@app.route('/api/v1/register', methods=['POST'])
def process_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify(success=False, message="Missing fields")
    
    db = get_db()
    try:
        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'user'))
        db.commit()
        return jsonify(success=True)
    except sqlite3.IntegrityError:
        return jsonify(success=False, message="Username already taken")

@app.route('/api/v1/process_login', methods=['POST'])
def process_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    db = get_db()
    result = db.execute("SELECT username, password, role FROM users WHERE username = ?", (username,)).fetchone()
    
    if result and check_password_hash(result['password'], password):
        token = jwt.encode({'username': result['username'], 'role': result['role']}, JWT_SECRET, algorithm='HS256')
        response = make_response(jsonify(success=True))
        response.set_cookie('token', token, httponly=True)
        return response
    
    return jsonify(success=False)

@app.route('/admin')
def admin():
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    if user_ip != '127.0.0.1':
        return "Access Denied: Administrative interface is only accessible from localhost.", 403

    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        if decoded.get('role') == 'admin':
            db = get_db()
            users = db.execute('SELECT username, role FROM users WHERE username="flag" OR username="admin"').fetchall()
            return render_template('admin.html', users=users)
        return "Not authorized", 401
    except jwt.InvalidTokenError:
        return redirect(url_for('login'))
    
init_db()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)