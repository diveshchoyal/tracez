"""TraceZ Backend — Comprehensive Test Suite."""

import os
import sys
from pathlib import Path

# Add backend directory to path so app is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db, User, BlocklistEntry
from app.utils.crypto import hash_password, generate_api_key

# --- Setup Test Database ---
TEST_DATABASE_URL = "sqlite:///./test_tracez.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# Override dependency
app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

def setup_module(module):
    """Create a clean database before running tests."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Create test admin
    admin_user = User(
        email="admin@test.com",
        hashed_password=hash_password("adminpass123"),
        api_key="tz_admin_test_key",
        role="ADMIN",
        is_active=True
    )
    db.add(admin_user)
    
    # Seed a blocklist entry
    blocked = BlocklistEntry(
        domain="malicious-site.tk",
        category="phishing",
        source="test_feed"
    )
    db.add(blocked)
    db.commit()
    db.close()

def teardown_module(module):
    """Clean up test database."""
    Base.metadata.drop_all(bind=engine)
    if os.path.exists("./test_tracez.db"):
        try:
            os.remove("./test_tracez.db")
        except Exception:
            pass

# --- Tests ---

def test_health():
    """Verify health check endpoint returns 200 and valid JSON."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

def test_signup_login():
    """Verify signup flow, login flow, and authentication."""
    # Test Signup
    signup_payload = {
        "email": "user@test.com",
        "password": "SecurePassword123"
    }
    response = client.post("/api/auth/signup", json=signup_payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "user@test.com"
    assert data["role"] == "USER"
    assert "api_key" in data

    # Test Login
    login_payload = {
        "email": "user@test.com",
        "password": "SecurePassword123"
    }
    response = client.post("/api/auth/login", json=login_payload)
    assert response.status_code == 200
    login_data = response.json()
    assert "access_token" in login_data
    assert login_data["user"]["email"] == "user@test.com"

def test_scan_allowlist():
    """Verify scanning an allowlisted domain returns SAFE immediately."""
    response = client.post(
        "/api/scan/url",
        json={"url": "https://google.com/search?q=test"}
    )
    # The scan route should be accessible without credentials but accepts them
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] == 0

def test_scan_blocked_domain():
    """Verify that scanning a domain in the blocklist returns DANGEROUS."""
    # Headers with API Key
    headers = {"X-TraceZ-API-Key": "tz_admin_test_key"}
    response = client.post(
        "/api/scan/url",
        json={"url": "http://malicious-site.tk/login"},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "DANGEROUS"
    assert data["risk_score"] >= 80

def test_quick_scan():
    """Verify quick scanning endpoint works and doesn't require keys."""
    response = client.post(
        "/api/scan/url/quick",
        json={"url": "http://malicious-site.tk/login"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["on_blocklist"] is True
    assert data["verdict"] == "DANGEROUS"

def test_admin_metrics_denied():
    """Verify standard users or unauthenticated clients cannot fetch admin metrics."""
    # 1. Unauthenticated client
    client.cookies.clear()
    response = client.get("/api/admin/metrics")
    assert response.status_code == 401  # Unauthorized

    # 2. Authenticated standard user
    login_payload = {
        "email": "user@test.com",
        "password": "SecurePassword123"
    }
    client.post("/api/auth/login", json=login_payload)
    response = client.get("/api/admin/metrics")
    assert response.status_code == 403  # Forbidden


def test_admin_metrics_approved():
    """Verify admin user can fetch system metrics."""
    # Admin login
    login_payload = {
        "email": "admin@test.com",
        "password": "adminpass123"
    }
    response = client.post("/api/auth/login", json=login_payload)
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/api/admin/metrics", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "users_count" in data
    assert "scans_count" in data

if __name__ == "__main__":
    import traceback
    print("[*] Running standalone backend verification tests...")
    setup_module(None)
    try:
        test_health()
        print("[OK] test_health passed")
        test_signup_login()
        print("[OK] test_signup_login passed")
        test_scan_allowlist()
        print("[OK] test_scan_allowlist passed")
        test_scan_blocked_domain()
        print("[OK] test_scan_blocked_domain passed")
        test_quick_scan()
        print("[OK] test_quick_scan passed")
        test_admin_metrics_denied()
        print("[OK] test_admin_metrics_denied passed")
        test_admin_metrics_approved()
        print("[OK] test_admin_metrics_approved passed")
        print("\n[+] ALL TESTS COMPLETED SUCCESSFULLY!")
    except AssertionError as e:
        print("\n[!] Test assertion failed!")
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected test error: {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        teardown_module(None)


