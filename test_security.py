import io
import re
import sqlite3
from types import SimpleNamespace

import pytest

import app as app_module
import db as database

flask_app = app_module.app

PASSWORD = "password123"
KEY = "correct-horse-battery"
SECRET = b"TOP SECRET PAYLOAD 12345"


# ---------------------------------------------------------------- fixtures
@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Fresh temp database + upload folder, and OTP capture (no real email)."""
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()
    monkeypatch.setattr(app_module, "UPLOAD_FOLDER", str(upload_dir))

    otps = {}
    monkeypatch.setattr(app_module, "send_otp",
                        lambda email, code: otps.__setitem__(email, code))

    flask_app.config.update(TESTING=True)
    with flask_app.app_context():
        database.init_db()
    return SimpleNamespace(otps=otps, upload_dir=upload_dir)


# ----------------------------------------------------------------- helpers
def query(sql, args=()):
    with flask_app.app_context():
        return database.get_db().execute(sql, args).fetchall()


def execute(sql, args=()):
    with flask_app.app_context():
        db = database.get_db()
        db.execute(sql, args)
        db.commit()


def make_user(env, email):
    """Register + log in through the real flow (password, then OTP)."""
    client = flask_app.test_client()
    client.post("/register", data={"email": email, "password": PASSWORD})
    client.post("/login", data={"email": email, "password": PASSWORD})
    client.post("/verify", data={"code": env.otps[email]})
    return client


def upload(client, name="note.txt", content=SECRET,
           classification="Confidential", key=KEY):
    return client.post(
        "/upload",
        data={"file": (io.BytesIO(content), name),
              "classification": classification, "passphrase": key},
        content_type="multipart/form-data")


def create_share(owner, file_id, email, can_download=False, hours=24):
    data = {"email": email, "hours": str(hours)}
    if can_download:
        data["can_download"] = "on"
    resp = owner.post(f"/share/{file_id}", data=data)
    match = re.search(r"/s/([A-Za-z0-9_\-]+)", resp.get_data(as_text=True))
    assert match, "share link was not generated"
    return match.group(1)


@pytest.fixture()
def shared(env):
    """Owner uploads an encrypted file and shares it (view-only) with Bob."""
    owner = make_user(env, "owner@test.com")
    bob = make_user(env, "bob@test.com")
    upload(owner)
    file_id = query("SELECT id FROM files")[0]["id"]
    token = create_share(owner, file_id, "bob@test.com")
    return SimpleNamespace(env=env, owner=owner, bob=bob,
                           file_id=file_id, token=token)


# ============================================================ ENCRYPTION
def test_encrypted_file_is_not_plaintext_on_disk(env):
    owner = make_user(env, "owner@test.com")
    upload(owner)
    stored = query("SELECT stored_name FROM files")[0]["stored_name"]
    raw = (env.upload_dir / stored).read_bytes()
    assert SECRET not in raw


def test_wrong_key_rejected_and_right_key_works(env):
    owner = make_user(env, "owner@test.com")
    upload(owner)
    bad = owner.post("/download/1", data={"passphrase": "wrong-key-123"})
    assert b"Wrong key" in bad.data
    assert SECRET not in bad.data

    good = owner.post("/download/1", data={"passphrase": KEY})
    assert good.status_code == 200
    assert good.data == SECRET


def test_tampered_ciphertext_is_detected(env):
    owner = make_user(env, "owner@test.com")
    upload(owner)
    stored = query("SELECT stored_name FROM files")[0]["stored_name"]
    path = env.upload_dir / stored
    data = bytearray(path.read_bytes())
    data[0] ^= 0xFF                      # flip bits in the stored file
    path.write_bytes(bytes(data))

    resp = owner.post("/download/1", data={"passphrase": KEY})
    assert b"tampered" in resp.data
    assert SECRET not in resp.data


# ======================================================== ACCESS CONTROL
def test_unauthenticated_users_are_redirected_to_login(shared):
    anon = flask_app.test_client()
    for url in ["/dashboard", "/upload", "/download/1", f"/s/{shared.token}"]:
        resp = anon.get(url)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_other_user_cannot_download_my_file_idor(shared):
    resp = shared.bob.get(f"/download/{shared.file_id}")
    assert resp.status_code == 404


def test_disallowed_file_type_is_rejected(env):
    owner = make_user(env, "owner@test.com")
    upload(owner, name="malware.exe", content=b"MZ...")
    assert len(query("SELECT id FROM files")) == 0


# ============================================================ SHARE LINKS
def test_recipient_can_view_with_link_and_key(shared):
    resp = shared.bob.post(f"/s/{shared.token}",
                           data={"action": "view", "passphrase": KEY})
    assert resp.status_code == 200
    assert resp.data == SECRET


def test_recipient_with_wrong_key_is_denied(shared):
    resp = shared.bob.post(f"/s/{shared.token}",
                           data={"action": "view", "passphrase": "nope-nope-1"})
    assert SECRET not in resp.data


def test_link_is_useless_to_a_different_user(shared, env):
    eve = make_user(env, "eve@test.com")
    resp = eve.get(f"/s/{shared.token}")
    assert resp.status_code == 403


def test_view_only_share_blocks_download(shared):
    resp = shared.bob.post(f"/s/{shared.token}",
                           data={"action": "download", "passphrase": KEY})
    assert resp.status_code == 403


def test_revoked_link_stops_working_immediately(shared):
    assert shared.bob.get(f"/s/{shared.token}").status_code == 200
    share_id = query("SELECT id FROM shares")[0]["id"]
    shared.owner.post(f"/revoke/{share_id}")
    assert shared.bob.get(f"/s/{shared.token}").status_code == 404


def test_expired_link_stops_working(shared):
    execute("UPDATE shares SET expires_at = 1")      # far in the past
    assert shared.bob.get(f"/s/{shared.token}").status_code == 404


def test_only_owner_can_revoke_a_share(shared):
    share_id = query("SELECT id FROM shares")[0]["id"]
    resp = shared.bob.post(f"/revoke/{share_id}")
    assert resp.status_code == 404
    assert query("SELECT revoked FROM shares")[0]["revoked"] == 0


def test_raw_share_token_is_never_stored(shared):
    stored = [r["token_hash"] for r in query("SELECT token_hash FROM shares")]
    assert shared.token not in stored


# ============================================================= AUTH / OTP
def test_passwords_are_stored_hashed(env):
    make_user(env, "owner@test.com")
    stored = query("SELECT password_hash FROM users")[0]["password_hash"]
    assert PASSWORD not in stored
    assert len(stored) > 40


def test_login_error_does_not_reveal_which_field_was_wrong(env):
    make_user(env, "owner@test.com")
    c = flask_app.test_client()
    wrong_pw = c.post("/login", data={"email": "owner@test.com",
                                      "password": "badbadbad1"})
    no_user = c.post("/login", data={"email": "ghost@test.com",
                                     "password": "badbadbad1"})
    assert b"Invalid email or password." in wrong_pw.data
    assert b"Invalid email or password." in no_user.data


def test_otp_locks_after_five_wrong_attempts(env):
    make_user(env, "owner@test.com")
    c = flask_app.test_client()
    c.post("/login", data={"email": "owner@test.com", "password": PASSWORD})
    real_code = env.otps["owner@test.com"]

    for _ in range(5):
        c.post("/verify", data={"code": "000000"})
    c.post("/verify", data={"code": real_code})      # correct, but too late

    assert c.get("/dashboard").status_code == 302    # still not logged in


def test_otp_cannot_be_reused(env):
    make_user(env, "owner@test.com")
    c = flask_app.test_client()
    c.post("/login", data={"email": "owner@test.com", "password": PASSWORD})
    code = env.otps["owner@test.com"]
    c.post("/verify", data={"code": code})           # first use: OK
    c.get("/logout")

    c2 = flask_app.test_client()
    c2.post("/login", data={"email": "owner@test.com", "password": PASSWORD})
    # old code must not work for the new login attempt
    c2.post("/verify", data={"code": code})
    assert c2.get("/dashboard").status_code == 302