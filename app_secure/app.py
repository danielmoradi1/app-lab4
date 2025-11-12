# app_secure/app.py
"""
Säkrad Flask-app för labben (parametriserade queries, sanitized comments,
säker subprocess, CSP och sandboxed iframe för kommentarer).
"""

import sqlite3
from flask import Flask, g, request, render_template, redirect, url_for, make_response
import subprocess
import re
import os
import logging
import secrets
import bleach

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "db.sqlite3")
LOGFILE = os.path.join(os.path.dirname(BASE_DIR), "logs", "app_secure.log")
os.makedirs(os.path.dirname(LOGFILE), exist_ok=True)
logging.basicConfig(filename=LOGFILE, level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-demo-secret'


ALLOWED_TAGS = []   
ALLOWED_ATTRS = {}

# ------ DB helpers -------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ---------------- CSP + nonce ----------------
@app.after_request
def set_csp(response):
    nonce = secrets.token_urlsafe(16)
    # strict policy: allow only scripts from 'self' and no inline scripts
    csp = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    response.headers['Content-Security-Policy'] = csp
    # also other security headers (optional but recommended)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

# ---------------- Routes ----------------
@app.route('/')
def index():
    return redirect(url_for('products'))

# -------- Login (parametriserad SQL) --------
@app.route('/login', methods=['GET','POST'])
def login():
    message = None
    user = None
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','').strip()
        logging.info("LOGIN_ATTEMPT username=%s", username)

        db = get_db()
        # PARAMETRIZED query
        cur = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cur.fetchone()
        if user:
            logging.info("LOGIN_SUCCESS username=%s", username)
            message = f"Welcome, {user['username']}!"
        else:
            logging.info("LOGIN_FAILED username=%s", username)
            message = "Incorrect username or password"
    return render_template('login.html', message=message, user=user)

# -------- Products & search (escaped output) --------
@app.route('/products')
def products():
    q = request.args.get('q','')
    db = get_db()
    rows = db.execute("SELECT id, name, description FROM products").fetchall()
    # We pass q to the template but the template will escape the value
    return render_template('products.html', products=rows, query=q)

# -------- Product + comments (sanera input, iframe) --------
@app.route('/product/<int:pid>', methods=['GET'])
def product(pid):
    db = get_db()
    prod = db.execute("SELECT id, name, description FROM products WHERE id = ?", (pid,)).fetchone()
    return render_template('product.html', product=prod)

# Endpoint that delivers comments (rendered in a sandboxed iframe)
@app.route('/comments_iframe')
def comments_iframe():
    pid = request.args.get('product', '')
    try:
        pid_i = int(pid)
    except Exception:
        return "Invalid product", 400
    db = get_db()
    comments = db.execute("SELECT text, created_at FROM comments WHERE product_id = ? ORDER BY created_at DESC", (pid_i,)).fetchall()
    return render_template('comments_iframe.html', comments=comments, product_id=pid_i)

@app.route('/comments_post', methods=['POST'])
def comments_post():
    # POST endpoint that receives comment and sanitizes before storing
    pid = request.form.get('product_id','')
    comment = request.form.get('comment','')
    try:
        pid_i = int(pid)
    except Exception:
        return "Invalid product", 400
    # SANITIZE before storing with bleach (remove all HTML here)
    clean = bleach.clean(comment, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
    db = get_db()
    db.execute("INSERT INTO comments (product_id, text) VALUES (?, ?)", (pid_i, clean))
    db.commit()
    logging.info("COMMENT_ADDED product=%s len=%d", pid_i, len(clean))
    # redirect to iframe page so that parent reload does not happen
    return redirect(url_for('comments_iframe') + f"?product={pid_i}")

# -------- Diagnostics (secure subprocess) --------
HOST_RE = re.compile(r'^[A-Za-z0-9\.\-]+$')  # allowlist: letters, numbers, dot and dash

@app.route('/diag', methods=['GET'])
def diag():
    host = request.args.get('host', '127.0.0.1').strip()
    logging.info("DIAG_REQUEST host=%s", host)
    # Strictly validate input
    if not HOST_RE.match(host):
        output = "Invalid host"
        return render_template('diag.html', host=host, output=output)
    try:
        # secure subprocess: list format, no shell=True
        completed = subprocess.run(['ping', '-c', '1', host], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
        output = completed.stdout
    except Exception as e:
        output = f"Error: {e}"
    return render_template('diag.html', host=host, output=output)

# Debug helper (read-only, for testing)
@app.route('/_debug/comments')
def debug_comments():
    db = get_db()
    rows = db.execute("SELECT id, product_id, text FROM comments ORDER BY created_at DESC LIMIT 10").fetchall()
    return "<br>".join([f"{r['product_id']}: {r['text']}" for r in rows])

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
