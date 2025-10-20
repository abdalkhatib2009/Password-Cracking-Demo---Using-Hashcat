#!/usr/bin/env python3
"""
Password Cracker Demo - Flask (single-file)

Purpose: educational demo to show why weak passwords are dangerous.
- Lets users submit "weak" passwords via a form (for demo only).
- Stores username + hashed password in a local SQLite DB.
- Shows stored hashes and (optionally) can automate a local Hashcat run
  to demonstrate how easily weak hashes can be cracked using a wordlist.

IMPORTANT: Run this ONLY locally (e.g., in a VM or an isolated machine).
Do NOT deploy this on a public-facing server. This is for demonstration/teaching.

Security & environment notes about automated Hashcat:
- This script will NOT run Hashcat automatically unless you explicitly
  enable it by setting the environment variable AUTO_RUN_HASHCAT=1.
- If AUTO_RUN_HASHCAT=1 and hashcat binary exists in PATH, the app will
  attempt a short, time-limited Hashcat run (120 seconds) using a local
  wordlist (preferably a small subset of rockyou) and then show the result.
- The automated run is restricted to fast hash types only (md5, sha1, sha256).

Run:
  AUTO_RUN_HASHCAT=0 python cracker.py  # safe default (no auto run)
  or
  AUTO_RUN_HASHCAT=1 python cracker.py  # allow auto-run if hashcat present
"""

from flask import Flask, request, redirect, url_for, render_template_string, send_from_directory, abort
import sqlite3
import hashlib
import os
import subprocess
import shutil
from werkzeug.utils import secure_filename

# Optional bcrypt support
try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except Exception:
    BCRYPT_AVAILABLE = False

# Determine application directory in a sandbox-safe way.
try:
    APP_DIR = os.path.dirname(__file__) or os.getcwd()
except NameError:
    APP_DIR = os.getcwd()

# Ensure the app directory exists and is writable
os.makedirs(APP_DIR, exist_ok=True)

# Static directory for logo and other assets
STATIC_DIR = os.path.join(APP_DIR, 'static')
os.makedirs(STATIC_DIR, exist_ok=True)

DB_PATH = os.path.join(APP_DIR, 'demo_users.db')
ALLOWED_LOGO_EXT = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
LOGO_FILENAME = 'logo.png'  # stored as static/logo.png

# Whether automatic hashcat runs are allowed (explicit opt-in via env var)
AUTO_RUN_HASHCAT = os.environ.get('AUTO_RUN_HASHCAT', '0') == '1'
HASHCAT_BIN = shutil.which('hashcat')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4 MB upload limit

# Small built-in wordlist for quick demo (you can upload your own wordlist via the app if desired)
BUILT_IN_WORDS = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password1',
    'admin', 'letmein', 'welcome', 'iloveyou', '111111', '123123', 'passw0rd'
]

# Helper to try to find a rockyou-ish wordlist path
COMMON_WORDLIST_PATHS = [
    '/usr/share/wordlists/rockyou.txt',
    os.path.join(APP_DIR, 'rockyou.txt'),
]

SUPPORTED_AUTO_HASHCAT = {
    'md5': '0',
    'sha1': '100',
    'sha256': '1400',
}

TEMPLATE = '''
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Password Cracker Demo</title>
  <style>
    html,body { height:100%; margin:0 }
    body { font-family: Arial, sans-serif; display:flex; align-items:center; justify-content:center; background:#f6f8fa }
    .container { width:900px; max-width:96%; background:white; padding:24px; border-radius:12px; box-shadow:0 10px 30px rgba(0,0,0,0.08) }
    header { display:flex; align-items:center; gap:12px; margin-bottom:12px }
    .logo { height:64px; width:auto }
    h1 { margin:0 }
    form { display:flex; flex-direction:column; align-items:center }
    .row { width:100%; display:flex; gap:12px; margin:8px 0 }
    .row label { flex:1 }
    input[type=text], input[type=password], select { width:100%; padding:10px; border:1px solid #ddd; border-radius:6px }
    button { padding:10px 16px; border-radius:8px; background:#007bff; color:white; border:none; cursor:pointer }
    button.secondary { background:#6c757d }
    .muted { color:#666; font-size:0.9em }
    table { border-collapse: collapse; width:100%; margin-top:12px }
    th, td { border:1px solid #eee; padding:8px; text-align:left }
    footer { margin-top:18px; text-align:center; color:#777; font-size:0.9em; }
    pre { background:#f8f9fb; padding:8px; border-radius:6px; overflow:auto }
  </style>
</head>
<body>
  <div class="container">
    <header>
      {% if logo_exists %}
        <img src="/static/{{ logo_file }}" alt="Logo" class="logo">
      {% endif %}
      <div>
        <h1>Password Cracker Demo</h1>
        <div class="muted">Educational demo — run locally only.</div>
      </div>
    </header>

    <div style="margin-bottom:10px">
      <a href="/upload_logo">Upload / change logo</a> •
      <a href="/list">Stored users</a>
    </div>

    <div style="padding:12px;">
      <h3>Create demo user</h3>
      <form method="post" action="/store">
        <div class="row">
          <label>Username:<br><input type="text" name="username" required></label>
        </div>
        <div class="row">
          <label>Password:<br><input type="password" name="password" required></label>
        </div>
        <div class="row">
          <label>Hash Algorithm:<br>
            <select name="algo">
              <option value="md5">MD5 (UNSAFE)</option>
              <option value="sha1">SHA1 (UNSAFE)</option>
              <option value="sha256">SHA256 (not salted in this demo)</option>
              {% if bcrypt %}
              <option value="bcrypt">bcrypt (recommended for real use)</option>
              {% endif %}
            </select>
          </label>
        </div>
        <div class="row">
          <label>Optional salt (appended before hashing):<br><input type="text" name="salt"></label>
        </div>
        <div style="display:flex; gap:8px; justify-content:center; margin-top:12px">
          <button type="submit">Create user</button>
          <a href="/" class="secondary"><button type="button" class="secondary">Cancel</button></a>
        </div>
      </form>
    </div>

    {% if created is defined %}
      <div style="margin-top:18px; padding:12px; background:#f1f9ff; border-radius:8px">
        <strong>Stored:</strong> {{ created.username }} — algorithm: {{ created.algo }}<br>
        <strong>Hash:</strong> <code>{{ created.hash }}</code><br>
        {% if created.hashcat_cmd %}
          <div style="margin-top:8px">
            <strong>Hashcat command (to run locally):</strong>
            <pre>{{ created.hashcat_cmd }}</pre>
            {% if created.auto_ran %}
              <div style="margin-top:6px"><strong>Auto-run result:</strong>
                <pre>{{ created.auto_output }}</pre>
              </div>
            {% endif %}
          </div>
        {% endif %}
      </div>
    {% endif %}

    <!-- footer -->
    <footer>
      Developed by Eng CyberWolf &nbsp;|&nbsp;
   
    </footer>
  </div> <!-- .container -->
</body>
</html>
'''

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    algo TEXT,
                    salt TEXT,
                    hash TEXT
                  )''')
    conn.commit()
    conn.close()

def store_user(username, algo, salt, hashed):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('REPLACE INTO users (username, algo, salt, hash) VALUES (?, ?, ?, ?)',
                (username, algo, salt or '', hashed))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT username FROM users')
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT username, algo, salt, hash FROM users WHERE username=?', (username,))
    r = cur.fetchone()
    conn.close()
    return r

@app.route('/')
def index():
    users = get_all_users()
    logo_path = os.path.join(STATIC_DIR, LOGO_FILENAME)
    logo_exists = os.path.isfile(logo_path)
    return render_template_string(TEMPLATE, users=users, bcrypt=BCRYPT_AVAILABLE, logo_exists=logo_exists, logo_file=LOGO_FILENAME)

@app.route('/store', methods=['POST'])
def store():
    username = request.form.get('username')
    if username:
        username = username.strip()
    password = request.form.get('password')
    algo = request.form.get('algo')
    salt = request.form.get('salt') or ''

    if not username or not password or not algo:
        return 'Missing fields', 400

    # Compute hash according to selected algo
    if algo == 'md5':
        h = hashlib.md5((password + salt).encode('utf-8')).hexdigest()
    elif algo == 'sha1':
        h = hashlib.sha1((password + salt).encode('utf-8')).hexdigest()
    elif algo == 'sha256':
        h = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    elif algo == 'bcrypt' and BCRYPT_AVAILABLE:
        h = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    else:
        return 'Unsupported hashing option (bcrypt not installed?)', 400

    store_user(username, algo, salt, h)

    # Prepare a hash file for hashcat and the hashcat command to show the user
    hashfile = os.path.join(APP_DIR, f'{username}_hash.txt')
    with open(hashfile, 'w', encoding='utf-8') as fh:
        fh.write(h + "\n")

    # find a wordlist
    wordlist = None
    for p in COMMON_WORDLIST_PATHS:
        if os.path.isfile(p):
            wordlist = p
            break

    # fallback to a tiny built-in list saved to a temp file (fast to run)
    if not wordlist:
        tmpwl = os.path.join(APP_DIR, 'demo_wordlist.txt')
        # write a small built-in wordlist to a temp file (use safe quoting)
        with open(tmpwl, 'w', encoding='utf-8') as f:
            f.write("\n".join(BUILT_IN_WORDS) + "\n")
        wordlist = tmpwl

    hashcat_cmd = None
    auto_output = None
    auto_ran = False

    if algo in SUPPORTED_AUTO_HASHCAT:
        mode = SUPPORTED_AUTO_HASHCAT[algo]
        # build safe hashcat command (show to user)
        # --potfile-path set to a unique file to avoid polluting global pots
        potfile = os.path.join(APP_DIR, f'hashcat_{username}.potfile')
        hashcat_cmd = f"hashcat -m {mode} -a 0 {hashfile} {wordlist} --potfile-path {potfile} --quiet"

        # Only run hashcat automatically if explicitly allowed and binary exists
        if AUTO_RUN_HASHCAT and HASHCAT_BIN:
            auto_ran = True
            try:
                # run with a timeout to avoid extremely long runs in demos
                subprocess.run([HASHCAT_BIN, '-m', mode, '-a', '0', hashfile, wordlist, '--potfile-path', potfile, '--quiet'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
                # after run, ask hashcat to show cracked results
                show = subprocess.run([HASHCAT_BIN, '--show', '-m', mode, hashfile, '--potfile-path', potfile],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out = show.stdout.decode('utf-8', errors='ignore').strip()
                auto_output = out or '(no password recovered in automatic run)'
            except subprocess.TimeoutExpired:
                auto_output = '(hashcat automatic run timed out)'
            except Exception as e:
                auto_output = f'(failed to run hashcat automatically: {e})'
    else:
        # unsupported (e.g., bcrypt) — we still produce a suggested manual command but no auto-run
        hashcat_cmd = None

    created = {
        'username': username,
        'algo': algo,
        'hash': h,
        'hashcat_cmd': hashcat_cmd,
        'auto_ran': auto_ran,
        'auto_output': auto_output,
    }

    users = get_all_users()
    logo_path = os.path.join(STATIC_DIR, LOGO_FILENAME)
    logo_exists = os.path.isfile(logo_path)
    return render_template_string(TEMPLATE, created=created, users=users, bcrypt=BCRYPT_AVAILABLE, logo_exists=logo_exists, logo_file=LOGO_FILENAME)

@app.route('/list')
def list_users():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT username, algo, salt, hash FROM users')
    rows = cur.fetchall()
    conn.close()

    html = '<h2>Stored users</h2><table><tr><th>Username</th><th>Algo</th><th>Salt</th><th>Hash</th></tr>'
    for u, a, s, h in rows:
        html += f'<tr><td>{u}</td><td>{a}</td><td>{s or "-"} </td><td style="font-family:monospace">{h}</td></tr>'
    html += '</table><p><a href="/">Back</a></p>'
    return html

def allowed_logo_filename(filename: str) -> bool:
    if not filename:
        return False
    ext = filename.rsplit('.', 1)[-1].lower()
    return ext in ALLOWED_LOGO_EXT

@app.route('/upload_logo', methods=['GET', 'POST'])
def upload_logo():
    if request.method == 'GET':
        html = '<h2>Upload Logo</h2>'
        html += '<form method="post" enctype="multipart/form-data">'
        html += '<input type="file" name="logo"> <button type="submit">Upload</button>'
        html += '</form>'
        html += '<p>Accepted formats: png, jpg, jpeg, gif, svg. Max size: 4MB.</p>'
        html += '<p><a href="/">Back</a></p>'
        return html

    file = request.files.get('logo')
    if not file:
        return 'No file uploaded', 400
    filename = secure_filename(file.filename)
    if not allowed_logo_filename(filename):
        return 'Invalid file type', 400
    save_path = os.path.join(STATIC_DIR, LOGO_FILENAME)
    try:
        file.save(save_path)
    except Exception as e:
        return f'Failed to save file: {e}', 500
    return redirect(url_for('index'))

@app.route('/static/<path:filename>')
def static_files(filename):
    # Serve static files from STATIC_DIR; fallback to abort if not found
    full = os.path.join(STATIC_DIR, filename)
    if not os.path.isfile(full):
        abort(404)
    return send_from_directory(STATIC_DIR, filename)

if __name__ == '__main__':
    init_db()
    print('Bcrypt available:', BCRYPT_AVAILABLE)
    print('Database path:', DB_PATH)
    print('AUTO_RUN_HASHCAT enabled:' , AUTO_RUN_HASHCAT, 'hashcat_bin:', HASHCAT_BIN)
    # sandbox-safe: don't enable debugger/reloader by default
    debug_env = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(host='127.0.0.1', port=5000, debug=debug_env, use_reloader=False)
