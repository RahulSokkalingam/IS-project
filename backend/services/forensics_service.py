"""Forensics Service Routines.

Coordinates log parsing and mounted drive file integrity inspection with the SQLite database.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Union, Optional
from sqlalchemy.orm import Session

from app.models import Device, FileArtifact
from parsers.usb_parser import USBLogParser, ParsedUSBDevice
from analyzers.file_analyzer import FileAnalyzer, AnalyzedFileArtifact


def _to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ForensicsService:
    """High-level service routines for forensics data ingestion and integrity analysis."""

    @classmethod
    def ingest_usb_log(
        cls,
        content: str,
        filename: Optional[str] = None,
        db: Optional[Session] = None
    ) -> List[Device]:
        """Parses raw log content and registers discovered USB devices into the database."""
        lower_name = (filename or "").lower()
        if "setupapi" in lower_name or "[Device Install Log]" in content:
            parsed_devices = USBLogParser.parse_setupapi(content)
        else:
            parsed_devices = USBLogParser.parse_linux_log(content)

        saved_devices: List[Device] = []

        if db is not None:
            for p in parsed_devices:
                existing = db.query(Device).filter(Device.serial_number == p.serial_number).first()
                if existing:
                    if p.volume_label and not existing.volume_label:
                        existing.volume_label = p.volume_label
                    if p.first_connected:
                        if existing.first_connected is None or _to_utc(p.first_connected) < _to_utc(existing.first_connected):
                            existing.first_connected = p.first_connected
                    if p.last_connected:
                        if existing.last_connected is None or _to_utc(p.last_connected) > _to_utc(existing.last_connected):
                            existing.last_connected = p.last_connected
                    db.commit()
                    db.refresh(existing)
                    saved_devices.append(existing)
                else:
                    new_dev = Device(**p.to_dict())
                    db.add(new_dev)
                    db.commit()
                    db.refresh(new_dev)
                    saved_devices.append(new_dev)

        return saved_devices

    @classmethod
    def analyze_and_ingest_drive(
        cls,
        target_dir: Union[str, Path],
        device_id: int,
        db: Session
    ) -> Dict[str, Any]:
        """Scans a mounted volume directory, inspects file integrity, and commits records to SQLite."""
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise ValueError(f"Device with ID {device_id} does not exist.")

        # 1. Scan directory & extract metadata + hashes + flags
        artifacts = FileAnalyzer.scan_directory(target_dir)

        # 2. Persist to database linked to device_id
        inserted_count = FileAnalyzer.persist_artifacts(artifacts, device_id=device_id, db=db)

        # 3. Compile forensic summary
        suspicious_items = [a for a in artifacts if a.flag_suspicious]

        return {
            "device_id": device_id,
            "device_serial": device.serial_number,
            "target_dir": str(target_dir),
            "total_files_scanned": len(artifacts),
            "records_persisted": inserted_count,
            "suspicious_count": len(suspicious_items),
            "clean_count": len(artifacts) - len(suspicious_items),
            "artifacts": [a.model_dump() for a in artifacts],
        }

    @classmethod
    def ingest_live_system_history(cls, db: Session) -> List[Device]:
        """Automatically reads real system logs and hardware registry to extract actual USB history."""
        import platform
        from services.drive_detector import (
            detect_removable_drives,
            get_windows_registry_usb_devices,
        )

        saved_devices: List[Device] = []

        # 1. Parse physical setupapi log if available on Windows
        if platform.system() == "Windows":
            setupapi_path = Path(r"C:\Windows\INF\setupapi.dev.log")
            if setupapi_path.exists():
                try:
                    content = setupapi_path.read_text(encoding="utf-8", errors="ignore")
                    log_devs = cls.ingest_usb_log(content, filename="setupapi.dev.log", db=db)
                    saved_devices.extend(log_devs)
                except Exception:
                    pass

            # 2. Extract hardware records directly from Windows Registry
            reg_devices = get_windows_registry_usb_devices()
            for r in reg_devices:
                serial = r["serial_number"]
                existing = db.query(Device).filter(Device.serial_number == serial).first()
                if existing:
                    if r.get("volume_label") and (not existing.volume_label or existing.volume_label.startswith("USB Device")):
                        existing.volume_label = r["volume_label"]
                    if r.get("vendor_id") and existing.vendor_id == "0000":
                        existing.vendor_id = r["vendor_id"]
                    if r.get("product_id") and existing.product_id == "0001":
                        existing.product_id = r["product_id"]
                    db.commit()
                    db.refresh(existing)
                    if existing not in saved_devices:
                        saved_devices.append(existing)
                else:
                    new_dev = Device(
                        vendor_id=r["vendor_id"],
                        product_id=r["product_id"],
                        serial_number=serial,
                        volume_label=r["volume_label"],
                        first_connected=r["first_connected"],
                        last_connected=r["last_connected"],
                    )
                    db.add(new_dev)
                    db.commit()
                    db.refresh(new_dev)
                    saved_devices.append(new_dev)

        elif platform.system() == "Linux":
            # Check Linux syslog / messages
            for log_cand in ("/var/log/syslog", "/var/log/messages"):
                p = Path(log_cand)
                if p.exists():
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                        sys_devs = cls.ingest_usb_log(content, filename=p.name, db=db)
                        saved_devices.extend(sys_devs)
                        break
                    except Exception:
                        pass

        # 3. Correlate with currently mounted removable drives
        try:
            live_drives = detect_removable_drives()
            for ld in live_drives:
                mount = ld["mount_point"]
                label = f"{ld['volume_label']} ({mount.rstrip(os.sep)})"
                serial = ld.get("serial_number") or f"LIVE_MOUNT_{mount.replace(':', '').replace(os.sep, '')}"
                vid = ld.get("vendor_id") or "0000"
                pid = ld.get("product_id") or "0000"

                existing = db.query(Device).filter(
                    (Device.serial_number == serial) | (Device.volume_label.like(f"%{mount}%"))
                ).first()

                if existing:
                    existing.volume_label = label
                    existing.last_connected = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(existing)
                    if existing not in saved_devices:
                        saved_devices.append(existing)
                else:
                    new_dev = Device(
                        vendor_id=vid,
                        product_id=pid,
                        serial_number=serial,
                        volume_label=label,
                        first_connected=datetime.now(timezone.utc),
                        last_connected=datetime.now(timezone.utc),
                    )
                    db.add(new_dev)
                    db.commit()
                    db.refresh(new_dev)
                    saved_devices.append(new_dev)
        except Exception:
            pass

        return saved_devices
