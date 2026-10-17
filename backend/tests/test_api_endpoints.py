"""Unit and Integration Tests for Phase 4 REST API Endpoints in backend/app.py."""

import sys
import os
from pathlib import Path
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Ensure backend root directory is in sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.database import Base, get_db
from app.models import Device, FileArtifact
from app import app

TESTS_DIR = Path(__file__).resolve().parent
SAMPLE_LOG = TESTS_DIR / "sample_data" / "setupapi.dev.log"
SYSLOG_SAMPLE = TESTS_DIR / "sample_data" / "syslog_usb.log"
MOCK_FILES_DIR = TESTS_DIR / "mock_files"


@pytest.fixture
def client_and_session():
    """Provides isolated in-memory SQLite database and test client."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client, TestingSession

    app.dependency_overrides.clear()


def test_endpoint_health(client_and_session):
    client, _ = client_and_session
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "online"


def test_endpoint_1_upload_log(client_and_session):
    client, _ = client_and_session

    # 1. Success case with Windows setupapi log
    with open(SAMPLE_LOG, "rb") as f:
        res = client.post(
            "/api/upload-log",
            files={"file": ("setupapi.dev.log", f, "text/plain")}
        )
    assert res.status_code == 200
    devices = res.json()
    assert len(devices) == 3
    vids = {d["vendor_id"] for d in devices}
    assert "0781" in vids
    assert "0951" in vids
    assert "1FC9" in vids

    # 2. Success case with Linux syslog
    with open(SYSLOG_SAMPLE, "rb") as f:
        res2 = client.post(
            "/api/upload-log",
            files={"file": ("syslog_usb.log", f, "text/plain")}
        )
    assert res2.status_code == 200

    # 3. Error case: empty file
    res_empty = client.post(
        "/api/upload-log",
        files={"file": ("empty.log", b"", "text/plain")}
    )
    assert res_empty.status_code == 400
    assert "empty" in res_empty.json()["detail"].lower()


def test_endpoint_2_scan_drive(client_and_session):
    client, Session = client_and_session

    # Seed device to link
    with open(SAMPLE_LOG, "rb") as f:
        client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})

    devs_res = client.get("/api/devices")
    target_dev_id = devs_res.json()[0]["id"]

    # 1. Success drive scan
    scan_res = client.post("/api/scan-drive", json={
        "device_id": target_dev_id,
        "target_path": str(MOCK_FILES_DIR),
    })
    assert scan_res.status_code == 200
    data = scan_res.json()
    assert data["total_files_scanned"] == 6
    assert data["suspicious_count"] == 5
    assert data["clean_count"] == 1
    assert len(data["artifacts"]) == 6

    # 2. Error case: non-existent folder
    bad_res = client.post("/api/scan-drive", json={
        "device_id": target_dev_id,
        "target_path": "Z:/NonExistent/Folder/Path",
    })
    assert bad_res.status_code == 404

    # 3. Error case: target path is a file, not a directory
    file_as_dir = client.post("/api/scan-drive", json={
        "device_id": target_dev_id,
        "target_path": str(MOCK_FILES_DIR / "innocent_document.pdf"),
    })
    assert file_as_dir.status_code == 400


def test_endpoint_3_get_devices(client_and_session):
    client, _ = client_and_session

    # Upload logs to populate
    with open(SAMPLE_LOG, "rb") as f:
        client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})

    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 3
    assert all("vendor_id" in d and "serial_number" in d for d in data)


def test_endpoint_4_get_timeline(client_and_session):
    client, _ = client_and_session

    # Upload logs
    with open(SAMPLE_LOG, "rb") as f:
        client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})

    # 1. Default timeline (descending)
    res = client.get("/api/timeline?order=desc")
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 3
    assert all("event_id" in e and "event_type" in e for e in events)

    # 2. Ascending order
    res_asc = client.get("/api/timeline?order=asc")
    assert res_asc.status_code == 200
    events_asc = res_asc.json()
    assert len(events_asc) == len(events)
    if len(events_asc) >= 2:
        assert events_asc[0]["timestamp"] <= events_asc[-1]["timestamp"]

    # 3. Filter by device_id
    dev_id = events[0]["device_id"]
    res_filtered = client.get(f"/api/timeline?device_id={dev_id}")
    assert res_filtered.status_code == 200
    assert all(e["device_id"] == dev_id for e in res_filtered.json())


def test_endpoint_5_get_files(client_and_session):
    client, _ = client_and_session

    # Populate device and scan drive
    with open(SAMPLE_LOG, "rb") as f:
        client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})
    dev_id = client.get("/api/devices").json()[0]["id"]
    client.post("/api/scan-drive", json={
        "device_id": dev_id,
        "target_path": str(MOCK_FILES_DIR),
    })

    # 1. Get all files
    res_all = client.get("/api/files")
    assert res_all.status_code == 200
    assert len(res_all.json()) == 6

    # 2. Filter suspicious only
    res_susp = client.get("/api/files?suspicious_only=true")
    assert res_susp.status_code == 200
    assert len(res_susp.json()) == 5
    assert all(f["flag_suspicious"] is True for f in res_susp.json())

    # 3. Filter by device ID
    res_dev = client.get(f"/api/files?device_id={dev_id}")
    assert res_dev.status_code == 200
    assert len(res_dev.json()) == 6

    # 4. Search by keyword
    res_search = client.get("/api/files?search=autorun")
    assert res_search.status_code == 200
    assert len(res_search.json()) >= 1
    assert "autorun.inf" in res_search.json()[0]["file_path"]


def test_endpoint_6_get_stats(client_and_session):
    client, _ = client_and_session

    # Populate
    with open(SAMPLE_LOG, "rb") as f:
        client.post("/api/upload-log", files={"file": ("setupapi.dev.log", f, "text/plain")})
    dev_id = client.get("/api/devices").json()[0]["id"]
    client.post("/api/scan-drive", json={
        "device_id": dev_id,
        "target_path": str(MOCK_FILES_DIR),
    })

    res = client.get("/api/stats")
    assert res.status_code == 200
    stats = res.json()

    assert stats["total_devices"] == 3
    assert stats["total_files_scanned"] == 6
    assert stats["flagged_suspicious_files"] == 5
    assert stats["clean_files"] == 1
    assert len(stats["recent_connections"]) <= 5
    assert len(stats["recent_connections"]) >= 1


def test_endpoint_detect_drives(client_and_session):
    client, _ = client_and_session
    res = client.get("/api/detect-drives")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    for drive in res.json():
        assert "mount_point" in drive
        assert "volume_label" in drive
        assert "is_removable" in drive


def test_endpoint_ingest_live_log(client_and_session):
    client, _ = client_and_session
    res = client.post("/api/ingest-live-log")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
    # Each returned item is a DeviceSummary
    for dev in res.json():
        assert "id" in dev
        assert "vendor_id" in dev
        assert "product_id" in dev
        assert "serial_number" in dev


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__]))

