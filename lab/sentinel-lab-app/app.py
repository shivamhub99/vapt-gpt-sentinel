"""
Sentinel Lab App
A lightweight Flask e-commerce demonstration application with intentionally planted
security vulnerabilities for defensive closed-loop research and verification.

Intentionally Planted Vulnerabilities:
1. CWE-89: SQL Injection in `/api/search?q=` (string concatenation in raw query)
2. CWE-79: Reflected XSS in `/api/greet?name=` (unescaped HTML response)
3. CWE-798: Hardcoded API Secret Key
4. CWE-1395: Vulnerable pinned dependencies in requirements.txt (Werkzeug==2.2.2, requests==2.25.1)
5. CWE-639: Insecure Direct Object Reference (IDOR) in `/api/orders/<id>`
6. CWE-693 / CWE-16: Missing security headers (CSP, HSTS, X-Content-Type-Options) & permissive CORS
"""

import os
import sqlite3
from typing import Any, Dict, List

from flask import Flask, Response, jsonify, make_response, request

app = Flask(__name__)

# --- INTENTIONAL PLANT #3: Hardcoded API Secret Key (CWE-798) ---
API_SECRET_KEY = "SENTINEL-SECRET-KEY-9988-PROD-DO-NOT-LEAK"

DB_PATH = os.environ.get("LAB_DB_PATH", "lab.db")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize lab database with tables and seed data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )
        """
    )

    # Seed data if empty
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO products (name, description, price) VALUES (?, ?, ?)",
            [
                ("Laptop Pro 15", "High performance developer laptop", 1299.99),
                ("Mechanical Keyboard", "RGB mechanical gaming and typing keyboard", 89.99),
                ("Wireless Mouse", "Ergonomic wireless mouse with USB receiver", 29.99),
                ("USB-C Monitor", "27-inch 4K IPS display with power delivery", 349.99),
            ],
        )

    cursor.execute("SELECT COUNT(*) FROM orders")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO orders (user_id, item, total, status) VALUES (?, ?, ?, ?)",
            [
                (1, "Laptop Pro 15", 1299.99, "Delivered"),
                (2, "Mechanical Keyboard", 89.99, "Processing"),
                (1, "Wireless Mouse", 29.99, "Shipped"),
            ],
        )

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO users (username, email) VALUES (?, ?)",
            [
                ("alice", "alice@example.com"),
                ("bob", "bob@example.com"),
            ],
        )

    conn.commit()
    conn.close()


# Ensure DB is seeded on import
init_db()


# --- INTENTIONAL PLANT #6: Missing Security Headers & Insecure CORS (CWE-693 / CWE-16) ---
@app.after_request
def apply_headers(response: Response) -> Response:
    # Intentionally missing HSTS, CSP, X-Content-Type-Options
    # Permissive wildcard CORS
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.route("/", methods=["GET"])
def index() -> Response:
    """Interactive landing page for sentinel-lab-app."""
    html_page = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel Lab App</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --primary: #38bdf8;
            --accent: #818cf8;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --danger: #f43f5e;
            --success: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 2rem; display: flex; justify-content: center; }
        .container { max-width: 900px; width: 100%; }
        header { text-align: center; margin-bottom: 2.5rem; }
        h1 { font-size: 2.2rem; color: var(--primary); margin-bottom: 0.5rem; }
        p.subtitle { color: var(--text-muted); font-size: 1.1rem; }
        .badge { display: inline-block; background: rgba(56, 189, 248, 0.15); color: var(--primary); padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; margin-top: 0.75rem; border: 1px solid rgba(56, 189, 248, 0.3); }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .card h2 { font-size: 1.3rem; margin-bottom: 0.75rem; display: flex; align-items: center; justify-content: space-between; }
        .card p { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 1rem; }
        .input-group { display: flex; gap: 0.5rem; margin-bottom: 0.75rem; }
        input[type="text"] { flex: 1; padding: 0.6rem 1rem; border-radius: 6px; border: 1px solid var(--border); background: #0b1120; color: #fff; font-size: 0.95rem; }
        input[type="text"]:focus { outline: none; border-color: var(--primary); }
        button, a.btn { padding: 0.6rem 1.2rem; border-radius: 6px; font-size: 0.95rem; font-weight: 500; cursor: pointer; text-decoration: none; border: none; display: inline-flex; align-items: center; gap: 0.5rem; }
        .btn-primary { background: var(--primary); color: #0b1120; font-weight: 600; }
        .btn-primary:hover { opacity: 0.9; }
        .btn-secondary { background: var(--surface-hover); color: var(--text); border: 1px solid var(--border); }
        .btn-secondary:hover { background: #475569; }
        .quick-links { display: flex; flex-wrap: wrap; gap: 0.5rem; }
        .quick-link { font-size: 0.85rem; padding: 0.25rem 0.6rem; border-radius: 4px; background: rgba(255, 255, 255, 0.05); color: var(--text-muted); text-decoration: none; border: 1px solid var(--border); }
        .quick-link:hover { color: var(--primary); border-color: var(--primary); }
        .quick-link.vuln { color: #fda4af; border-color: rgba(244, 63, 94, 0.3); background: rgba(244, 63, 94, 0.1); }
        .quick-link.vuln:hover { border-color: var(--danger); }
        .api-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; }
        .api-item { background: #0b1120; padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid var(--border); text-decoration: none; color: var(--text); display: block; }
        .api-item:hover { border-color: var(--accent); }
        .api-item .method { font-size: 0.75rem; font-weight: 700; color: var(--accent); margin-right: 0.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Sentinel Lab Target Application</h1>
            <p class="subtitle">Controlled testbed application for defensive closed-loop vulnerability remediation research</p>
            <span class="badge">Running in Isolated Docker Network (Port 8080)</span>
        </header>

        <!-- Product Search (SQLi test) -->
        <div class="card">
            <h2>
                <span>🔍 Product Catalog Search</span>
                <span style="font-size: 0.8rem; color: #f43f5e;">CWE-89 Lab Target</span>
            </h2>
            <p>Query the internal SQLite database for products.</p>
            <form action="/api/search" method="GET" class="input-group">
                <input type="text" name="q" placeholder="Search keyword (e.g., Laptop)..." value="Laptop">
                <button type="submit" class="btn btn-primary">Search</button>
            </form>
            <div class="quick-links">
                <span style="font-size: 0.85rem; color: var(--text-muted); align-self: center;">Test queries:</span>
                <a class="quick-link" href="/api/search?q=Laptop">q=Laptop (Normal)</a>
                <a class="quick-link" href="/api/search?q=Mouse">q=Mouse (Normal)</a>
                <a class="quick-link vuln" href="/api/search?q=' OR 1=1 --">q=' OR 1=1 -- (Planted SQLi)</a>
            </div>
        </div>

        <!-- User Greeting (XSS test) -->
        <div class="card">
            <h2>
                <span>💬 User Greeting</span>
                <span style="font-size: 0.8rem; color: #f43f5e;">CWE-79 Lab Target</span>
            </h2>
            <p>Generates a dynamic user welcome response.</p>
            <form action="/api/greet" method="GET" class="input-group">
                <input type="text" name="name" placeholder="Enter username..." value="Alice">
                <button type="submit" class="btn btn-primary">Greet</button>
            </form>
            <div class="quick-links">
                <span style="font-size: 0.85rem; color: var(--text-muted); align-self: center;">Test inputs:</span>
                <a class="quick-link" href="/api/greet?name=Alice">name=Alice (Normal)</a>
                <a class="quick-link vuln" href="/api/greet?name=%3Ch1%3EHacked%3C/h1%3E">name=&lt;h1&gt;Hacked&lt;/h1&gt; (Planted XSS)</a>
            </div>
        </div>

        <!-- Orders & IDOR -->
        <div class="card">
            <h2>
                <span>📦 Customer Orders</span>
                <span style="font-size: 0.8rem; color: #f43f5e;">CWE-639 Lab Target</span>
            </h2>
            <p>Inspect order records by ID.</p>
            <div class="quick-links">
                <a class="quick-link" href="/api/orders/1">Order #1 (Alice's Order)</a>
                <a class="quick-link vuln" href="/api/orders/2">Order #2 (Bob's Order - IDOR Access)</a>
            </div>
        </div>

        <!-- Direct API Endpoints -->
        <div class="card">
            <h2><span>⚡ Raw API Endpoints</span></h2>
            <div class="api-list">
                <a class="api-item" href="/api/health"><span class="method">GET</span>/api/health</a>
                <a class="api-item" href="/api/products"><span class="method">GET</span>/api/products</a>
                <a class="api-item" href="/api/orders/1"><span class="method">GET</span>/api/orders/1</a>
            </div>
        </div>
    </div>
</body>
</html>
"""
    return Response(html_page, mimetype="text/html")


@app.route("/api/health", methods=["GET"])
def healthcheck() -> Response:
    """Basic healthcheck endpoint for readiness probes."""
    return jsonify({"status": "healthy", "app": "sentinel-lab-app", "version": "1.0.0"})



@app.route("/api/products", methods=["GET"])
def list_products() -> Response:
    """Returns catalog of products."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, price FROM products")
    rows = cursor.fetchall()
    conn.close()
    products: List[Dict[str, Any]] = [dict(row) for row in rows]
    return jsonify({"products": products})


# --- INTENTIONAL PLANT #1: SQL Injection (CWE-89) ---
@app.route("/api/search", methods=["GET"])
def search_products() -> Response:
    """
    Search products by name query.
    Vulnerability: Direct string interpolation into raw SQL query without parameter binding.
    """
    query = request.args.get("q", "")
    conn = get_db_connection()
    cursor = conn.cursor()
    # INSECURE: Formatted string execution
    raw_sql = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%'"
    cursor.execute(raw_sql)
    rows = cursor.fetchall()
    conn.close()
    results: List[Dict[str, Any]] = [dict(row) for row in rows]
    return jsonify({"query": query, "count": len(results), "results": results})


# --- INTENTIONAL PLANT #2: Reflected XSS (CWE-79) ---
@app.route("/api/greet", methods=["GET"])
def greet_user() -> Response:
    """
    Greets a user by name.
    Vulnerability: Direct unescaped reflection of user-controlled query param into HTML body.
    """
    name = request.args.get("name", "Guest")
    # INSECURE: Unescaped interpolation in HTML
    html_content = f"<html><body><div id='greeting'>Welcome back, {name}!</div></body></html>"
    return Response(html_content, mimetype="text/html")


# --- INTENTIONAL PLANT #5: Insecure Direct Object Reference / IDOR (CWE-639) ---
@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id: int) -> Response:
    """
    Retrieves order details by ID.
    Vulnerability: Access control check absent; any caller can view any user's order details.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, user_id, item, total, status FROM orders WHERE id = ?", (order_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Order not found"}), 404
    return jsonify({"order": dict(row)})


@app.route("/api/validate-key", methods=["POST"])
def validate_key() -> Response:
    """Validates provided authorization key against the API key."""
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    if key == API_SECRET_KEY:
        return jsonify({"valid": True, "message": "Key is valid"})
    return jsonify({"valid": False, "error": "Invalid API key"}), 401


@app.route("/api/login", methods=["POST"])
def login() -> Response:
    """Sets a demonstration session cookie without HttpOnly or Secure flags."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "alice")
    resp = make_response(jsonify({"message": f"Logged in as {username}"}))
    # INSECURE: Cookie missing httponly=True, secure=True, samesite
    resp.set_cookie("session_id", f"sess_{username}_demo123", httponly=False, secure=False)
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
