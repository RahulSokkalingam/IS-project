import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from services.drive_detector import (
    detect_removable_drives,
    is_drive_removable,
    get_windows_registry_usb_devices,
)


def test_is_drive_removable_flags():
    assert is_drive_removable("E:\\", "rw,removable") is True
    assert is_drive_removable("/media/usb", "nosuid,nodev,removable") is True
    # Fixed system drive
    assert is_drive_removable("C:\\", "rw,fixed") is False


def test_detect_removable_drives_structure():
    drives = detect_removable_drives()
    assert isinstance(drives, list)
    for d in drives:
        assert "mount_point" in d
        assert "volume_label" in d
        assert "file_system" in d
        assert "total_bytes" in d
        assert "free_bytes" in d
        assert "percent_used" in d
        assert d["is_removable"] is True


def test_get_windows_registry_usb_devices():
    devices = get_windows_registry_usb_devices()
    assert isinstance(devices, list)
    for dev in devices:
        assert "vendor_id" in dev
        assert "product_id" in dev
        assert "serial_number" in dev


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__]))

