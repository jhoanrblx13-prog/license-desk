import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "license_desk.db"
SECRET = os.environ.get("LICENSE_DESK_SECRET", "license-desk-demo-secret")

app = FastAPI(title="License Desk")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=str(ROOT / "templates"))


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"{salt}${digest}"


def check_password(password: str, stored: str) -> bool:
    salt, digest = stored.split("$", 1)
    trial = hash_password(password, salt).split("$", 1)[1]
    return hmac.compare_digest(trial, digest)


def sign(value: str) -> str:
    mac = hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}.{mac}"


def unsign(token: str) -> str | None:
    if "." not in token:
        return None
    value, mac = token.rsplit(".", 1)
    expected = hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return None
    return value


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS customers (
              id INTEGER PRIMARY KEY,
              name TEXT NOT NULL,
              email TEXT NOT NULL,
              plan TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS licenses (
              id INTEGER PRIMARY KEY,
              customer_id INTEGER NOT NULL,
              license_key TEXT NOT NULL,
              plan TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(customer_id) REFERENCES customers(id)
            );
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              target TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            """
        )
        existing = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        if not existing:
            users = [
                ("DemoMode", "D!D!D!", "demo"),
                ("admin", "YardAdmin!42", "admin"),
            ]
            conn.executemany(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                [(name, hash_password(password), role) for name, password, role in users],
            )
            customers = [
                ("Northline Studio", "a***@northline.example", "Desk"),
                ("Harbor & Co", "m***@harbor.example", "Bench"),
                ("Fieldnote Labs", "s***@fieldnote.example", "Yard"),
                ("Static Reply", "j***@static.example", "Desk"),
            ]
            for name, email, plan in customers:
                conn.execute(
                    "INSERT INTO customers (name, email, plan, created_at) VALUES (?, ?, ?, ?)",
                    (name, email, plan, now()),
                )
            rows = conn.execute("SELECT id, plan FROM customers").fetchall()
            for index, row in enumerate(rows, start=1042):
                status = "revoked" if index == 1044 else "active"
                key = f"NX-DEMO-{index}"
                conn.execute(
                    "INSERT INTO licenses (customer_id, license_key, plan, status, created_at) VALUES (?, ?, ?, ?, ?)",
                    (row["id"], key, row["plan"], status, now()),
                )
        if conn.execute("SELECT COUNT(*) AS n FROM audit").fetchone()["n"] == 0:
            conn.execute(
                "INSERT INTO audit (actor, action, target, created_at) VALUES (?, ?, ?, ?)",
                ("admin", "issued", "NX-DEMO-1042", now()),
            )
            conn.execute(
                "INSERT INTO audit (actor, action, target, created_at) VALUES (?, ?, ?, ?)",
                ("admin", "revoked", "NX-DEMO-1044", now()),
            )


init_db()


def current_user(request: Request):
    token = request.cookies.get("session")
    if not token:
        return None
    username = unsign(token)
    if not username:
        return None
    with connect() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def require_user(request: Request):
    user = current_user(request)
    if user is None:
        return None
    return user


def deny_demo(user) -> None:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="DemoMode cannot change records")


def stats():
    with connect() as conn:
        customers = conn.execute("SELECT COUNT(*) AS n FROM customers").fetchone()["n"]
        active = conn.execute("SELECT COUNT(*) AS n FROM licenses WHERE status = 'active'").fetchone()["n"]
        revoked = conn.execute("SELECT COUNT(*) AS n FROM licenses WHERE status = 'revoked'").fetchone()["n"]
    return {"customers": customers, "active": active, "revoked": revoked}


def record(conn, actor: str, action: str, target: str) -> None:
    conn.execute(
        "INSERT INTO audit (actor, action, target, created_at) VALUES (?, ?, ?, ?)",
        (actor, action, target, now()),
    )


def mask_key(key: str, role: str) -> str:
    if role == "admin":
        return key
    head, _, _tail = key.rpartition("-")
    return f"{head}-••••"


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if current_user(request):
        return RedirectResponse("/app", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with connect() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not check_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Unknown user or password."},
            status_code=401,
        )
    response = RedirectResponse("/app", status_code=303)
    response.set_cookie("session", sign(user["username"]), httponly=True, samesite="lax")
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("session")
    return response


@app.get("/app", response_class=HTMLResponse)
def customers_page(request: Request, q: str = ""):
    user = require_user(request)
    if user is None:
        return RedirectResponse("/", status_code=303)
    with connect() as conn:
        customers = conn.execute(
            "SELECT * FROM customers WHERE name LIKE ? ORDER BY id",
            (f"%{q.strip()}%",),
        ).fetchall()
    return templates.TemplateResponse(
        request,
        "customers.html",
        {"title": "Customers", "page": "customers", "user": user, "customers": customers, "stats": stats(), "q": q},
    )


@app.get("/app/licenses", response_class=HTMLResponse)
def licenses_page(request: Request, q: str = "", status: str = "all"):
    user = require_user(request)
    if user is None:
        return RedirectResponse("/", status_code=303)
    status = status if status in {"all", "active", "revoked"} else "all"
    query = """
        SELECT licenses.*, customers.name AS customer_name
        FROM licenses JOIN customers ON customers.id = licenses.customer_id
        WHERE customers.name LIKE ?
    """
    params: list = [f"%{q.strip()}%"]
    if status != "all":
        query += " AND licenses.status = ?"
        params.append(status)
    query += " ORDER BY licenses.id DESC"
    with connect() as conn:
        customers = conn.execute("SELECT * FROM customers ORDER BY name").fetchall()
        rows = conn.execute(query, params).fetchall()
    licenses = []
    for row in rows:
        item = dict(row)
        item["display_key"] = mask_key(item["license_key"], user["role"])
        licenses.append(item)
    return templates.TemplateResponse(
        request,
        "licenses.html",
        {
            "title": "Licenses",
            "page": "licenses",
            "user": user,
            "customers": customers,
            "licenses": licenses,
            "stats": stats(),
            "q": q,
            "status": status,
        },
    )


@app.get("/app/licenses/{license_id}", response_class=HTMLResponse)
def license_detail(license_id: int, request: Request):
    user = require_user(request)
    if user is None:
        return RedirectResponse("/", status_code=303)
    with connect() as conn:
        row = conn.execute(
            """
            SELECT licenses.*, customers.name AS customer_name, customers.email AS customer_email
            FROM licenses JOIN customers ON customers.id = licenses.customer_id
            WHERE licenses.id = ?
            """,
            (license_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="License not found")
    item = dict(row)
    item["display_key"] = mask_key(item["license_key"], user["role"])
    return templates.TemplateResponse(
        request,
        "license.html",
        {"title": "License", "page": "licenses", "user": user, "license": item, "stats": stats()},
    )


@app.get("/app/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    user = require_user(request)
    if user is None:
        return RedirectResponse("/", status_code=303)
    with connect() as conn:
        events = conn.execute("SELECT * FROM audit ORDER BY id DESC").fetchall()
    return templates.TemplateResponse(
        request,
        "audit.html",
        {"title": "Audit", "page": "audit", "user": user, "events": events, "stats": stats()},
    )


@app.post("/customers")
def add_customer(request: Request, name: str = Form(...), email: str = Form(...), plan: str = Form(...)):
    user = require_user(request)
    if user is None:
        return RedirectResponse("/", status_code=303)
    deny_demo(user)
    with connect() as conn:
        conn.execute(
            "INSERT INTO customers (name, email, plan, created_at) VALUES (?, ?, ?, ?)",
            (name.strip(), email.strip(), plan.strip(), now()),
        )
        record(conn, user["username"], "created customer", name.strip())
    return RedirectResponse("/app", status_code=303)


@app.post("/licenses")
def issue_license(request: Request, customer_id: int = Form(...), plan: str = Form(...)):
    user = require_user(request)
    if user is None:
        return RedirectResponse("/", status_code=303)
    deny_demo(user)
    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) AS n FROM licenses").fetchone()["n"]
        key = f"NX-DEMO-{1042 + count}"
        conn.execute(
            "INSERT INTO licenses (customer_id, license_key, plan, status, created_at) VALUES (?, ?, ?, 'active', ?)",
            (customer_id, key, plan, now()),
        )
        record(conn, user["username"], "issued", key)
    return RedirectResponse("/app/licenses", status_code=303)


@app.post("/licenses/{license_id}/revoke")
def revoke_license(license_id: int, request: Request):
    user = require_user(request)
    if user is None:
        return RedirectResponse("/", status_code=303)
    deny_demo(user)
    with connect() as conn:
        row = conn.execute("SELECT license_key FROM licenses WHERE id = ?", (license_id,)).fetchone()
        conn.execute("UPDATE licenses SET status = 'revoked' WHERE id = ?", (license_id,))
        if row:
            record(conn, user["username"], "revoked", row["license_key"])
    return RedirectResponse(f"/app/licenses/{license_id}", status_code=303)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
