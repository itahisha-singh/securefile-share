import io
import os
import time
import uuid
import hmac
import secrets
import hashlib
import smtplib
from email.message import EmailMessage

from cryptography.exceptions import InvalidTag
from flask import (Flask, render_template, request, redirect,
                   url_for, flash, session, send_file, abort)
from flask_login import (LoginManager, UserMixin, login_user,
                         logout_user, login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import db as database
import crypto_utils

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.teardown_appcontext(database.close_db)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024   # 10 MB limit

ALLOWED_EXT = {"pdf", "txt", "xlsx", "pptx", "docx"}
CLASSIFICATIONS = ["Public", "Private", "Confidential", "Secret"]

login_manager = LoginManager(app)
login_manager.login_view = "login"

OTP_TTL_SECONDS = 300      # code valid for 5 minutes
OTP_MAX_ATTEMPTS = 5       # wrong guesses allowed per code


# ---------- User model ----------
class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]


@login_manager.user_loader
def load_user(user_id):
    row = database.get_db().execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return User(row) if row else None


# ---------- OTP helpers ----------
def hash_otp(code):
    return hmac.new(
        app.config["SECRET_KEY"].encode(),
        code.encode(),
        hashlib.sha256
    ).hexdigest()


def create_otp(user_id):
    code = f"{secrets.randbelow(1_000_000):06d}"
    db = database.get_db()
    db.execute("DELETE FROM otps WHERE user_id = ?", (user_id,))
    db.execute(
        "INSERT INTO otps (user_id, code_hash, expires_at) VALUES (?, ?, ?)",
        (user_id, hash_otp(code), time.time() + OTP_TTL_SECONDS))
    db.commit()
    return code


def send_otp(email, code):
    host = os.environ.get("SMTP_HOST")
    if not host:
        # Dev mode: no email server configured, print the code in the terminal
        print(f"\n[DEV MODE] OTP for {email}: {code}\n")
        return
    msg = EmailMessage()
    msg["Subject"] = "Your SecureFile Share login code"
    msg["From"] = os.environ["SMTP_USER"]
    msg["To"] = email
    msg.set_content(f"Your verification code is {code}. It expires in 5 minutes.")
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", 587))) as server:
        server.starttls()
        server.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
        server.send_message(msg)


# ---------- Routes ----------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if "@" not in email or len(password) < 8:
            flash("Enter a valid email and a password of at least 8 characters.")
            return render_template("register.html")

        db = database.get_db()
        if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            flash("That email is already registered.")
            return render_template("register.html")

        db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                   (email, generate_password_hash(password)))
        db.commit()
        flash("Account created. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        row = database.get_db().execute(
            "SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        # Same message for wrong email or wrong password (no user enumeration)
        if not row or not check_password_hash(row["password_hash"], password):
            flash("Invalid email or password.")
            return render_template("login.html")

        code = create_otp(row["id"])
        send_otp(row["email"], code)
        session["pending_user"] = row["id"]
        return redirect(url_for("verify"))
    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    user_id = session.get("pending_user")
    if not user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        db = database.get_db()
        row = db.execute("SELECT * FROM otps WHERE user_id = ?",
                         (user_id,)).fetchone()

        if (not row or time.time() > row["expires_at"]
                or row["attempts"] >= OTP_MAX_ATTEMPTS):
            session.pop("pending_user", None)
            flash("Code expired or too many attempts. Please log in again.")
            return redirect(url_for("login"))

        if not hmac.compare_digest(row["code_hash"], hash_otp(code)):
            db.execute("UPDATE otps SET attempts = attempts + 1 WHERE id = ?",
                       (row["id"],))
            db.commit()
            flash("Invalid code.")
            return render_template("verify.html")

        # Success: delete the code so it can't be reused
        db.execute("DELETE FROM otps WHERE user_id = ?", (user_id,))
        db.commit()
        session.pop("pending_user", None)
        user_row = db.execute("SELECT * FROM users WHERE id = ?",
                              (user_id,)).fetchone()
        login_user(User(user_row))
        return redirect(url_for("dashboard"))

    return render_template("verify.html")


@app.route("/dashboard")
@login_required
def dashboard():
    files = database.get_db().execute(
        "SELECT * FROM files WHERE owner_id = ? ORDER BY id DESC",
        (current_user.id,)).fetchall()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        classification = request.form.get("classification", "")
        passphrase = request.form.get("passphrase", "")

        if not f or not f.filename:
            flash("Choose a file.")
            return render_template("upload.html", classes=CLASSIFICATIONS)
        if classification not in CLASSIFICATIONS:
            flash("Invalid classification.")
            return render_template("upload.html", classes=CLASSIFICATIONS)

        original = secure_filename(f.filename)
        ext = original.rsplit(".", 1)[-1].lower() if "." in original else ""
        if ext not in ALLOWED_EXT:
            flash("Allowed types: " + ", ".join(sorted(ALLOWED_EXT)))
            return render_template("upload.html", classes=CLASSIFICATIONS)

        encrypt = classification != "Public"
        if encrypt and len(passphrase) < 8:
            flash("Encryption key must be at least 8 characters.")
            return render_template("upload.html", classes=CLASSIFICATIONS)

        data = f.read()
        size = len(data)
        stored_name = uuid.uuid4().hex      # random name on disk, not user-controlled
        salt = nonce = None
        if encrypt:
            salt, nonce, data = crypto_utils.encrypt_bytes(
                data, passphrase, stored_name)

        with open(os.path.join(UPLOAD_FOLDER, stored_name), "wb") as out:
            out.write(data)

        db = database.get_db()
        db.execute(
            """INSERT INTO files (owner_id, original_name, stored_name,
               classification, encrypted, salt, nonce, size)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (current_user.id, original, stored_name, classification,
             1 if encrypt else 0, salt, nonce, size))
        db.commit()
        flash(f"Uploaded {original} as {classification}"
              + (" (encrypted)." if encrypt else "."))
        return redirect(url_for("dashboard"))

    return render_template("upload.html", classes=CLASSIFICATIONS)


def get_owned_file(file_id):
    # Ownership check in the query itself: other users' IDs return 404
    row = database.get_db().execute(
        "SELECT * FROM files WHERE id = ? AND owner_id = ?",
        (file_id, current_user.id)).fetchone()
    if not row:
        abort(404)
    return row


@app.route("/download/<int:file_id>", methods=["GET", "POST"])
@login_required
def download(file_id):
    row = get_owned_file(file_id)
    with open(os.path.join(UPLOAD_FOLDER, row["stored_name"]), "rb") as fh:
        data = fh.read()

    if row["encrypted"]:
        if request.method == "GET":
            return render_template("download.html", file=row)
        passphrase = request.form.get("passphrase", "")
        try:
            data = crypto_utils.decrypt_bytes(
                data, passphrase, row["salt"], row["nonce"], row["stored_name"])
        except InvalidTag:
            flash("Wrong key, or the file was tampered with.")
            return render_template("download.html", file=row)

    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=row["original_name"])


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


@app.route("/share/<int:file_id>", methods=["GET", "POST"])
@login_required
def share(file_id):
    file_row = get_owned_file(file_id)
    db = database.get_db()
    new_link = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        can_download = 1 if request.form.get("can_download") else 0
        try:
            hours = max(1, min(int(request.form.get("hours", "24")), 720))
        except ValueError:
            hours = 24

        if "@" not in email:
            flash("Enter a valid recipient email.")
        elif email == current_user.email:
            flash("You already own this file.")
        else:
            token = secrets.token_urlsafe(32)
            db.execute(
                """INSERT INTO shares (file_id, recipient_email, token_hash,
                   can_download, expires_at) VALUES (?, ?, ?, ?, ?)""",
                (file_id, email, hash_token(token), can_download,
                 time.time() + hours * 3600))
            db.commit()
            # Shown only once: the raw token is never stored
            new_link = url_for("open_share", token=token, _external=True)

    shares = db.execute(
        "SELECT * FROM shares WHERE file_id = ? ORDER BY id DESC",
        (file_id,)).fetchall()
    return render_template("share.html", file=file_row, shares=shares,
                           new_link=new_link, now=time.time())


@app.route("/revoke/<int:share_id>", methods=["POST"])
@login_required
def revoke(share_id):
    db = database.get_db()
    row = db.execute(
        """SELECT s.id, s.file_id, f.owner_id FROM shares s
           JOIN files f ON f.id = s.file_id WHERE s.id = ?""",
        (share_id,)).fetchone()
    if not row or row["owner_id"] != current_user.id:
        abort(404)
    db.execute("UPDATE shares SET revoked = 1 WHERE id = ?", (share_id,))
    db.commit()
    flash("Access revoked.")
    return redirect(url_for("share", file_id=row["file_id"]))


@app.route("/shared")
@login_required
def shared_with_me():
    rows = database.get_db().execute(
        """SELECT s.*, f.original_name, f.classification FROM shares s
           JOIN files f ON f.id = s.file_id
           WHERE s.recipient_email = ? AND s.revoked = 0 AND s.expires_at > ?
           ORDER BY s.id DESC""",
        (current_user.email, time.time())).fetchall()
    return render_template("shared.html", shares=rows)


def load_valid_share(token):
    row = database.get_db().execute(
        """SELECT s.*, f.original_name, f.stored_name, f.classification,
                  f.encrypted, f.salt, f.nonce
           FROM shares s JOIN files f ON f.id = s.file_id
           WHERE s.token_hash = ?""", (hash_token(token),)).fetchone()
    if not row or row["revoked"] or time.time() > row["expires_at"]:
        abort(404)                      # same response for invalid/expired/revoked
    if row["recipient_email"] != current_user.email:
        abort(403)                      # link belongs to someone else
    return row


@app.route("/s/<token>", methods=["GET", "POST"])
@login_required
def open_share(token):
    row = load_valid_share(token)

    if request.method == "GET":
        return render_template("open_share.html", s=row)

    action = request.form.get("action", "view")
    if action == "download" and not row["can_download"]:
        abort(403)

    ext = row["original_name"].rsplit(".", 1)[-1].lower()
    if action == "view" and ext not in {"pdf", "txt"}:
        flash("Preview is only available for PDF and TXT. "
              "Ask the owner for download permission.")
        return render_template("open_share.html", s=row)

    with open(os.path.join(UPLOAD_FOLDER, row["stored_name"]), "rb") as fh:
        data = fh.read()

    if row["encrypted"]:
        try:
            data = crypto_utils.decrypt_bytes(
                data, request.form.get("passphrase", ""),
                row["salt"], row["nonce"], row["stored_name"])
        except InvalidTag:
            flash("Wrong key, or the file was tampered with.")
            return render_template("open_share.html", s=row)

    resp = send_file(io.BytesIO(data), as_attachment=(action == "download"),
                     download_name=row["original_name"])
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

if __name__ == "__main__":
    with app.app_context():
        database.init_db()

    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)