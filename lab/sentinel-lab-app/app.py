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
