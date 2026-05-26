"""TraceZ Extension API Integration Tests."""

import sys
import unittest
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, get_db, BlocklistEntry

# --- Setup Test Database ---
TEST_DATABASE_URL = "sqlite:///./test_tracez_extension.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override DB dependency
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

class TestExtensionAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=engine)

    def test_blocklist_version(self):
        """Test GET /api/blocklist/version endpoint (public/anonymous)."""
        response = client.get("/api/blocklist/version")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("version", data)
        self.assertIn("timestamp", data)

    def test_blocklist_download(self):
        """Test GET /api/blocklist/download endpoint (public/anonymous)."""
        response = client.get("/api/blocklist/download")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("domains", data)
        self.assertIn("version", data)
        self.assertTrue(isinstance(data["domains"], list))

    def test_scan_logging_and_history(self):
        """Test logging a scan from the extension and retrieving it from history."""
        # 1. Post local scan results to log endpoint
        payload = {
            "url": "http://suspicious-malware-sandbox-test.ru/login",
            "verdict": "DANGEROUS",
            "risk_score": 85,
            "signals": [
                {"layer": "local", "signal": "Domain mimics bank login form", "score": 45},
                {"layer": "local", "signal": "Suspicious TLD .ru", "score": 40}
            ],
            "reputation": {}
        }
        log_response = client.post("/api/scan/log", json=payload)
        self.assertEqual(log_response.status_code, 200)
        self.assertEqual(log_response.json(), {"status": "success"})

        # 2. Check if logged scan appears in history
        history_response = client.get("/api/scan/history")
        self.assertEqual(history_response.status_code, 200)
        history = history_response.json()
        
        # Verify our logged scan is at the top of the history list
        matching_scan = None
        for item in history:
            if item["url"] == "http://suspicious-malware-sandbox-test.ru/login":
                matching_scan = item
                break
                
        self.assertIsNotNone(matching_scan)
        self.assertEqual(matching_scan["verdict"], "DANGEROUS")
        self.assertEqual(matching_scan["risk_score"], 85)

    def test_public_block_allow_controls(self):
        """Test public block/allow domain override endpoints."""
        domain_name = "test-domain-block-override.com"
        
        # 1. Add domain to blocklist
        add_resp = client.post("/api/blocklist/add", json={"domain": domain_name, "category": "phishing"})
        self.assertEqual(add_resp.status_code, 200)
        self.assertEqual(add_resp.json()["status"], "success")

        # 2. Verify it exists in blocklist download
        dl_resp = client.get("/api/blocklist/download")
        self.assertIn(domain_name, dl_resp.json()["domains"])

        # 3. Remove domain from blocklist (Allow it)
        remove_resp = client.post("/api/blocklist/remove", json={"domain": domain_name, "category": "phishing"})
        self.assertEqual(remove_resp.status_code, 200)
        self.assertEqual(remove_resp.json()["status"], "success")

        # 4. Verify it was removed from blocklist download
        dl_resp_2 = client.get("/api/blocklist/download")
        self.assertNotIn(domain_name, dl_resp_2.json()["domains"])

if __name__ == "__main__":
    unittest.main()
