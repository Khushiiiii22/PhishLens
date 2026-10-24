from fastapi.testclient import TestClient
from unittest.mock import MagicMock
from main import app
from database import get_db


def test_health_db_success():
    """When DB executes SELECT 1 successfully, return 200 {'status': 'ok'}."""
    mock_db = MagicMock()
    mock_db.execute.return_value = None
    app.dependency_overrides[get_db] = lambda: mock_db

    client = TestClient(app)
    resp = client.get("/health/db")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    app.dependency_overrides.clear()


def test_health_db_unreachable():
    """When DB is unreachable, return 503 with no error details in body."""
    mock_db = MagicMock()
    mock_db.execute.side_effect = Exception("Connection refused to PostgreSQL host")
    app.dependency_overrides[get_db] = lambda: mock_db

    client = TestClient(app)
    resp = client.get("/health/db")
    assert resp.status_code == 503
    # No error details in the response body
    assert resp.content == b""

    app.dependency_overrides.clear()
