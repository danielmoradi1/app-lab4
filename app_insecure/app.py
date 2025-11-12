"""
app_insecure/app.py
Vulnerable Flask app
"""

import sqlite3
from flask import Flask, g, request, render_template, redirect, url_for
import subprocess
import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "db.sqlite3")
LOGFILE = os.path.join(os.path.dirname(BASE_DIR), "logs", "app.log")


os.makedirs(os.path.dirname(LOGFILE), exist_ok=True)
logging.basicConfig(filename=LOGFILE, level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret'

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

@app.route('/')
def index():
    return redirect(url_for('products'))

# -------------------------
# Login (vulnerable to SQLi)
# -------------------------
@app.route('/login', methods=['GET','POST'])
def login():
    message = None
    user = None
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        logging.info(f"LOGIN_ATTEMPT username={username}")

        # direct string format → SQLi possible
        db = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}';"
        try:
            cur = db.execute(query)
            user = cur.fetchone()
        except Exception as e:
            message = f"DB error: {e}"
        if user:
            logging.info(f"LOGIN_SUCCESS username={username}")
            message = f"Welcome, {user['username']}!"
        else:
            logging.info(f"LOGIN_FAILED username={username}")
            message = "Wrong username/password"
    return render_template('login.html', message=message, user=user)

# -------------------------
# Products (reflected XSS)
# -------------------------
@app.route('/products')
def products():
    q = request.args.get('q','')
    db = get_db()
    rows = db.execute("SELECT id, name, description FROM products").fetchall()
    return render_template('products.html', products=rows, query=q)

# -------------------------
# Product page + comments (stored XSS)
# -------------------------
@app.route('/product/<int:pid>', methods=['GET','POST'])
def product(pid):
    db = get_db()
    if request.method == 'POST':
        comment = request.form.get('comment','')
        db.execute("INSERT INTO comments (product_id, text) VALUES (?, ?)", (pid, comment))
        db.commit()
        logging.info(f"COMMENT_ADDED product={pid} comment_len={len(comment)}")
        return redirect(url_for('product', pid=pid))

    prod = db.execute("SELECT id, name, description FROM products WHERE id = ?", (pid,)).fetchone()
    comments = db.execute("SELECT text, created_at FROM comments WHERE product_id = ? ORDER BY created_at DESC", (pid,)).fetchall()
    return render_template('product.html', product=prod, comments=comments)

# -------------------------
# Diagnostics (command injection)
# -------------------------
@app.route('/diag', methods=['GET'])
def diag():
    host = request.args.get('host', '127.0.0.1')
    logging.info(f"DIAG_REQUEST host={host}")
    try:
        output = subprocess.check_output("ping -c 1 " + host, shell=True, stderr=subprocess.STDOUT, universal_newlines=True, timeout=5)
    except subprocess.CalledProcessError as e:
        output = f"Command failed:\n{e.output}"
    except Exception as e:
        output = f"Error: {e}"
    return render_template('diag.html', host=host, output=output)

# ---------------------
# to show DB contents
# --------------------
@app.route('/_debug/users')
def debug_users():
    db = get_db()
    rows = db.execute("SELECT id, username FROM users").fetchall()
    return "<br>".join([f"{r['id']}: {r['username']}" for r in rows])

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
