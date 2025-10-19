# Password Cracker Demo

**A small, single-file Flask app for local educational demonstrations** that shows why weak passwords are dangerous.
It lets instructors/students create demo accounts (username + password), stores the password as a hash in a local SQLite database, and generates a Hashcat command (and optionally runs a short, time-limited Hashcat job) to demonstrate how quickly weak hashes can be cracked.

> **Warning:** This project is strictly for local, educational use. **Do not** deploy it to any public or production-facing server.

---

## Features

* Add demo users with: `username`, masked `password`, `hash algorithm` (MD5, SHA1, SHA256, optional bcrypt).
* Stores users in a local SQLite DB (`demo_users.db`).
* Writes the single user's hash to `<username>_hash.txt`.
* Generates a safe Hashcat command for local use.
* Optional opt-in automatic Hashcat run (time-limited, CPU-focused).
* Logo upload support (`/upload_logo` → saved to `static/logo.png`).
* Simple, centered UI and footer credit line.
* Sandbox-safe: disables Flask debugger/reloader by default and uses safe file-handling.

---

## Files created at runtime

* `demo_users.db` — SQLite database storing demo users.
* `<username>_hash.txt` — the single user's hash file (for Hashcat).
* `demo_wordlist.txt` — fallback tiny wordlist (created if no system wordlist found).
* `static/logo.png` — uploaded logo (if used).
* `hashcat_<username>.potfile` — potfile used/created by Hashcat (if run).

---

## Requirements

* Python 3.8+
* Python packages:

  ```bash
  pip install flask
  # optional for bcrypt support
  pip install bcrypt
  ```
* (Optional) `hashcat` installed and available on `PATH` if you want auto-run capabilities.

---

## Quick start (safe default)

1. Clone the repository and open the project folder.
2. Run the app (safe — hashcat **will not** run automatically):

   ```bash
   python cracker.py
   ```
3. Open your browser to `http://127.0.0.1:5000` and create demo users.

---

## Enabling automatic Hashcat runs (local only — opt-in)

Automated Hashcat runs are disabled by default for safety. To enable:

1. Install `hashcat` and ensure it is on your `PATH` (`which hashcat` should return a path).
2. Start the app with the environment variable:

   ```bash
   export AUTO_RUN_HASHCAT=1      # Linux/macOS
   # or on Windows (PowerShell)
   $env:AUTO_RUN_HASHCAT = "1"
   python cracker.py
   ```

Notes:

* Auto-run is restricted to the fast hash types: MD5, SHA1, SHA256.
* Auto-run uses a 120-second timeout to avoid extremely long jobs.
* Do **not** enable AUTO_RUN_HASHCAT on public servers.

---

## How the Hashcat flow works

* After creating a user the app writes the hash to `<username>_hash.txt`.
* The app looks for a wordlist at common paths (e.g. `/usr/share/wordlists/rockyou.txt`) and falls back to a tiny built-in list (`demo_wordlist.txt`).
* The app prints a suggested Hashcat command such as:

  ```
  hashcat -m <mode> -a 0 <username>_hash.txt /path/to/wordlist.txt --potfile-path hashcat_<username>.potfile --quiet
  ```
* If auto-run is enabled, the app will run Hashcat with a timeout and then run `hashcat --show` to display recovered passwords (if any).

---

## Security & Usage Guidelines (READ CAREFULLY)

* **Run only in an isolated local environment** (virtual machine or dedicated demo machine).
* Do **not** use real passwords or real user accounts.
* The app writes temporary files and potfiles — remove them after demos if they contain sensitive data.
* Automatic execution of external binaries from a web app is inherently risky; the app requires explicit opt-in to do so.

---

## UI / Customization

* Logo: upload via `http://127.0.0.1:5000/upload_logo` (saved as `static/logo.png`).
* Footer: default credit text included. Edit the template in `cracker.py` if you want to change wording or styling.
* To change the fallback built-in wordlist, edit the `BUILT_IN_WORDS` list in the file.

---

## Suggested Improvements / Contributions

* Add a manual **Run Hashcat** button/route instead of auto-run for safer UX.
* Bundle a curated rockyou subset (1–2K entries) for quick demos.
* Add unit tests for hash and cracking helper functions (`pytest`).
* Add logging of cracking attempts and results to a DB table.
* Provide a Docker image for easier, isolated demos.

---

## License & Credits

* **Developer: Eng CyberWolf

This project is provided for educational use only. Use at your own risk.
