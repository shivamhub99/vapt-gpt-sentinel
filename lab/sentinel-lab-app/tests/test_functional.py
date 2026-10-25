"""
Functional Test Suite for sentinel-lab-app.

These tests verify legitimate application business logic and functionality.
In Phase 5, the verification loop will re-run these tests after applying any patch
to verify that functional behavior has not regressed.
"""

import os
import sys

import pytest

# Ensure lab app is importable
LAB_APP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if LAB_APP_DIR not in sys.path:
    sys.path.insert(0, LAB_APP_DIR)

from app import app, init_db  # noqa: E402


@pytest.fixture(scope="module")
def test_client():
    """Sets up Flask test client with an isolated in-memory or temp SQLite DB."""
    app.config["TESTING"] = True
    init_db()
    with app.test_client() as client:
        yield client


def test_index_page(test_client):
    """Verifies that the root landing page renders successfully."""
    response = test_client.get("/")
    assert response.status_code == 200
    assert "Sentinel Lab Target Application" in response.get_data(as_text=True)


def test_healthcheck(test_client):
    """Verifies that the service health probe responds with 200 OK."""
    response = test_client.get("/api/health")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["app"] == "sentinel-lab-app"


def test_list_products(test_client):
    """Verifies catalog retrieval returns seeded product records."""
    response = test_client.get("/api/products")
    assert response.status_code == 200
    data = response.get_json()
    assert "products" in data
    assert len(data["products"]) >= 4
    names = [p["name"] for p in data["products"]]
    assert "Laptop Pro 15" in names
    assert "Mechanical Keyboard" in names


def test_search_products_legitimate(test_client):
    """Verifies legitimate search for a product keyword returns matching items."""
    response = test_client.get("/api/search?q=Laptop")
    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] >= 1
    assert any("Laptop" in item["name"] for item in data["results"])


def test_search_products_no_match(test_client):
    """Verifies search with unmatched string returns empty list."""
    response = test_client.get("/api/search?q=NonExistentDeviceXYZ")
    assert response.status_code == 200
    data = response.get_json()
    assert data["count"] == 0
    assert data["results"] == []


def test_greet_user_legitimate(test_client):
    """Verifies that legitimate user greeting displays the expected greeting message."""
    response = test_client.get("/api/greet?name=Alice")
    assert response.status_code == 200
    assert "Welcome back, Alice!" in response.get_data(as_text=True)


def test_get_order_legitimate(test_client):
    """Verifies that querying an existing order returns valid order fields."""
    response = test_client.get("/api/orders/1")
    assert response.status_code == 200
    data = response.get_json()
    assert "order" in data
    order = data["order"]
    assert order["id"] == 1
    assert order["item"] == "Laptop Pro 15"
    assert order["total"] == 1299.99


def test_get_order_not_found(test_client):
    """Verifies that querying a non-existent order returns 404."""
    response = test_client.get("/api/orders/99999")
    assert response.status_code == 404


def test_validate_key_authorized(test_client):
    """Verifies that API key validation endpoint accepts the valid key."""
    # The key used by the lab app
    valid_key = "SENTINEL-SECRET-KEY-9988-PROD-DO-NOT-LEAK"
    response = test_client.post("/api/validate-key", json={"key": valid_key})
    assert response.status_code == 200
    data = response.get_json()
    assert data["valid"] is True


def test_validate_key_unauthorized(test_client):
    """Verifies that API key validation endpoint rejects invalid keys."""
    response = test_client.post("/api/validate-key", json={"key": "INVALID-KEY-1234"})
    assert response.status_code == 401
    data = response.get_json()
    assert data["valid"] is False
