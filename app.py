import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get("DATABASE", "notes.db")
app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
app.json.ensure_ascii = False

JWT_ALGORITHM = "HS256"
TOKEN_LIFETIME = timedelta(hours=1)
PASSWORD_MIN_BYTES = 8
PASSWORD_MAX_BYTES = 72


def db():
    if "conn" not in g:
        g.conn = sqlite3.connect(app.config["DATABASE"])
        g.conn.row_factory = sqlite3.Row
    return g.conn


@app.teardown_appcontext
def close_connection(_exc):
    conn = g.pop("conn", None)
    if conn is not None:
        conn.close()


def setup_database():
    with app.app_context():
        conn = db()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        conn.commit()


def json_body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def issue_token(user_id):
    now = datetime.now(timezone.utc)
    claims = {"sub": str(user_id), "iat": now, "exp": now + TOKEN_LIFETIME}
    return jwt.encode(claims, app.config["JWT_SECRET"], algorithm=JWT_ALGORITHM)


def authenticated(view):
    @wraps(view)
    def guard(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Authorization token required"), 401
        try:
            claims = jwt.decode(
                header.removeprefix("Bearer "),
                app.config["JWT_SECRET"],
                algorithms=[JWT_ALGORITHM],
                options={"require": ["exp", "sub"]},
            )
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid or expired token"), 401
        g.user_id = int(claims["sub"])
        return view(*args, **kwargs)

    return guard


@app.post("/auth/register")
def register():
    body = json_body()
    login = body.get("login")
    password = body.get("password")
    if not isinstance(login, str) or not isinstance(password, str) or not login or not password:
        return jsonify(error="login and password are required"), 400
    if not 3 <= len(login) <= 32:
        return jsonify(error="login must be 3-32 characters"), 400
    if not PASSWORD_MIN_BYTES <= len(password.encode()) <= PASSWORD_MAX_BYTES:
        return jsonify(error="password must be 8-72 bytes"), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        cursor = db().execute(
            "INSERT INTO users (login, password_hash) VALUES (?, ?)",
            (login, password_hash),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="login already taken"), 409
    return jsonify(id=cursor.lastrowid, login=str(escape(login))), 201


@app.post("/auth/login")
def login():
    body = json_body()
    login = body.get("login")
    password = body.get("password")
    if not isinstance(login, str) or not isinstance(password, str):
        return jsonify(error="login and password are required"), 400

    row = db().execute(
        "SELECT id, password_hash FROM users WHERE login = ?", (login,)
    ).fetchone()
    stored_hash = row["password_hash"].encode() if row else bcrypt.hashpw(b"x", bcrypt.gensalt())
    if not bcrypt.checkpw(password.encode()[:PASSWORD_MAX_BYTES], stored_hash) or row is None:
        return jsonify(error="invalid login or password"), 401
    return jsonify(access_token=issue_token(row["id"]))


@app.get("/api/data")
@authenticated
def list_notes():
    rows = db().execute(
        "SELECT id, title, body FROM notes WHERE owner_id = ? ORDER BY id DESC",
        (g.user_id,),
    ).fetchall()
    notes = [
        {"id": r["id"], "title": str(escape(r["title"])), "body": str(escape(r["body"]))}
        for r in rows
    ]
    return jsonify(notes=notes)


@app.post("/api/data")
@authenticated
def create_note():
    body = json_body()
    title = body.get("title")
    text = body.get("body")
    if not isinstance(title, str) or not isinstance(text, str) or not title or not text:
        return jsonify(error="title and body are required"), 400
    cursor = db().execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (g.user_id, title, text),
    )
    db().commit()
    return jsonify(id=cursor.lastrowid, title=str(escape(title)), body=str(escape(text))), 201


if __name__ == "__main__":
    setup_database()
    app.run(port=int(os.environ.get("PORT", "5001")))
