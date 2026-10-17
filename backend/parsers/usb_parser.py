"""Core USB Log Parser Module.

Parses forensic logs across operating systems:
1. Windows: setupapi.dev.log (extracting VID, PID, Serial, Volume/Disk names, timestamps).
2. Linux: dmesg and syslog (extracting bus events, idVendor, idProduct, SerialNumber, mounts, disconnects).

Normalizes extracted records into a unified structure matching the database schema.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict


class ParsedUSBDevice(BaseModel):
    """Normalized USB device metadata model matching the database schema."""
    vendor_id: str = Field(..., description="4-digit USB Vendor ID (hex)")
    product_id: str = Field(..., description="4-digit USB Product ID (hex)")
    serial_number: str = Field(..., description="Unique device serial number")
    volume_label: Optional[str] = Field(None, description="Extracted volume label or disk description")
    first_connected: Optional[datetime] = Field(None, description="Earliest recorded connection timestamp")
    last_connected: Optional[datetime] = Field(None, description="Latest recorded connection timestamp")

    model_config = ConfigDict(from_attributes=True)

    def to_dict(self) -> Dict[str, Union[str, Optional[str], Optional[datetime]]]:
        """Returns dictionary mapping directly to SQLAlchemy Device columns."""
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "volume_label": self.volume_label,
            "first_connected": self.first_connected,
            "last_connected": self.last_connected,
        }


class WindowsSetupApiParser:
    """Parser for Windows setupapi.dev.log device installation records."""

    SECTION_START_PATTERN = re.compile(
        r"^\s*>>>\s+\[Device Install \([^)]+\)\s+-\s+USB\\VID_([0-9a-fA-F]{4})&PID_([0-9a-fA-F]{4})\\([^\]\r\n]+)\]",
        re.MULTILINE | re.IGNORECASE,
    )
    SECTION_USBSTOR_PATTERN = re.compile(
        r"USBSTOR#(?:Disk&)?Ven_([^&#]+)&Prod_([^&#]+)(?:&Rev_[^#]+)?#([^#&\]\r\n]+)",
        re.IGNORECASE,
    )
    INLINE_VID_PID_PATTERN = re.compile(
        r"VID_([0-9a-fA-F]{4})&PID_([0-9a-fA-F]{4})",
        re.IGNORECASE,
    )
    TIMESTAMP_START_PATTERN = re.compile(
        r"Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
        re.IGNORECASE,
    )
    TIMESTAMP_END_PATTERN = re.compile(
        r"Section end\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
        re.IGNORECASE,
    )
    DISK_NAME_PATTERN = re.compile(
        r"dvi:\s+(?:Disk Name|Device Description):\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    DRIVE_LETTER_PATTERN = re.compile(
        r"dvi:\s+Assigned Drive Letter:\s*([A-Za-z]:)",
        re.IGNORECASE,
    )
    USBSTOR_DISK_PATTERN = re.compile(
        r"dvi:\s+Install Device:\s*USBSTOR\\Disk([^\\]+)\\",
        re.IGNORECASE,
    )

    @classmethod
    def parse_timestamp(cls, ts_str: str) -> Optional[datetime]:
        """Parses timestamp string from setupapi log into UTC datetime."""
        ts_str = ts_str.strip()
        for fmt in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
            try:
                dt = datetime.strptime(ts_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    @classmethod
    def parse(cls, content: str) -> List[ParsedUSBDevice]:
        """Parses raw setupapi.dev.log content into a list of normalized ParsedUSBDevice objects."""
        devices_by_serial: Dict[str, ParsedUSBDevice] = {}

        # Split content into sections starting with >>> (allowing optional leading indentation)
        sections = re.split(r"(?=^\s*>>>\s+\[)", content, flags=re.MULTILINE)

        for sec in sections:
            sec = sec.strip()
            if not sec:
                continue

            vid: Optional[str] = None
            pid: Optional[str] = None
            raw_serial: Optional[str] = None
            volume_label: Optional[str] = None

            # 1. Try standard USB\VID_xxxx&PID_xxxx section header
            match = cls.SECTION_START_PATTERN.search(sec)
            if match:
                vid = match.group(1).upper()
                pid = match.group(2).upper()
                raw_serial = match.group(3).strip()
            else:
                # 2. Try modern Windows USBSTOR header
                usbstor_match = cls.SECTION_USBSTOR_PATTERN.search(sec)
                if usbstor_match:
                    ven = usbstor_match.group(1).strip()
                    prod = usbstor_match.group(2).strip()
                    raw_serial = usbstor_match.group(3).strip()
                    volume_label = f"{ven} {prod.replace('_', ' ')} USB Device"

                    # Attempt to resolve inline VID/PID
                    inline_vp = cls.INLINE_VID_PID_PATTERN.search(sec)
                    if inline_vp:
                        vid = inline_vp.group(1).upper()
                        pid = inline_vp.group(2).upper()
                    else:
                        vid = (ven[:4].upper() if len(ven) >= 4 else ven.upper()).ljust(4, "0")
                        pid = "0001"

            if not raw_serial:
                continue

            # Clean composite instance suffixes like &0, &REV_0100
            serial = re.sub(r"&[0-9a-zA-Z]+$", "", raw_serial)

            # Extract timestamps
            start_time: Optional[datetime] = None
            end_time: Optional[datetime] = None

            start_match = cls.TIMESTAMP_START_PATTERN.search(sec)
            if start_match:
                start_time = cls.parse_timestamp(start_match.group(1))

            end_match = cls.TIMESTAMP_END_PATTERN.search(sec)
            if end_match:
                end_time = cls.parse_timestamp(end_match.group(1))

            first_conn = start_time or end_time
            last_conn = end_time or start_time

            # Extract volume label or disk description if not already set
            disk_match = cls.DISK_NAME_PATTERN.search(sec)
            if disk_match:
                volume_label = disk_match.group(1).strip()
            elif not volume_label:
                disk_stor = cls.USBSTOR_DISK_PATTERN.search(sec)
                if disk_stor:
                    volume_label = disk_stor.group(1).replace("_", " ").strip()

            drive_letter_match = cls.DRIVE_LETTER_PATTERN.search(sec)
            if drive_letter_match and volume_label:
                volume_label = f"{volume_label} ({drive_letter_match.group(1)})"

            # Merge or create device record
            if serial in devices_by_serial:
                dev = devices_by_serial[serial]
                if volume_label and not dev.volume_label:
                    dev.volume_label = volume_label

                # Update timestamps
                if first_conn and (dev.first_connected is None or first_conn < dev.first_connected):
                    dev.first_connected = first_conn
                if last_conn and (dev.last_connected is None or last_conn > dev.last_connected):
                    dev.last_connected = last_conn
            else:
                devices_by_serial[serial] = ParsedUSBDevice(
                    vendor_id=vid or "0000",
                    product_id=pid or "0000",
                    serial_number=serial,
                    volume_label=volume_label,
                    first_connected=first_conn,
                    last_connected=last_conn,
                )

        return list(devices_by_serial.values())


class LinuxUsbLogParser:
    """Parser for Linux kernel dmesg and /var/log/syslog USB connection events."""

    VID_PID_PATTERN = re.compile(
        r"idVendor\s*=\s*([0-9a-fA-F]{4})\s*,\s*idProduct\s*=\s*([0-9a-fA-F]{4})",
        re.IGNORECASE,
    )
    SERIAL_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+SerialNumber:\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    PRODUCT_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+Product:\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    MFR_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+Manufacturer:\s*([^\r\n]+)",
        re.IGNORECASE,
    )
    DISCONNECT_PATTERN = re.compile(
        r"usb\s+([0-9\.\-]+):\s+USB disconnect",
        re.IGNORECASE,
    )
    MOUNT_PATTERN = re.compile(
        r"(?:Mounted\s+\S+\s+at\s+|mount:\s+.*?on\s+)/media/[^/\s\r\n]+/([^\s\r\n]+)",
        re.IGNORECASE,
    )
    SYSLOG_TIME_PATTERN = re.compile(
        r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})",
    )
    ISO_TIME_PATTERN = re.compile(
        r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
    )
    DMESG_OFFSET_PATTERN = re.compile(
        r"\[\s*(\d+\.\d+)\s*\]",
    )

    @classmethod
    def parse_syslog_timestamp(cls, line: str, default_year: int = 2026) -> Optional[datetime]:
        """Extracts standard syslog (Mmm dd HH:MM:SS) or ISO8601 timestamp from log line."""
        iso_match = cls.ISO_TIME_PATTERN.search(line)
        if iso_match:
            raw = iso_match.group(1).replace("T", " ")
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

        syslog_match = cls.SYSLOG_TIME_PATTERN.search(line)
        if syslog_match:
            raw = f"{default_year} {syslog_match.group(1)}"
            try:
                # Format: 2026 Oct 05 10:14:22
                return datetime.strptime(raw, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        return None

    @classmethod
    def parse(cls, content: str, default_year: int = 2026) -> List[ParsedUSBDevice]:
        """Parses Linux syslog or dmesg content into a list of normalized ParsedUSBDevice objects."""
        # Temporary tracking by USB port (e.g. '1-1.2', '2-2')
        port_state: Dict[str, Dict] = {}
        # Final consolidated devices keyed by serial number
        devices_by_serial: Dict[str, ParsedUSBDevice] = {}

        lines = content.splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue

            ts = cls.parse_syslog_timestamp(line, default_year=default_year)

            # Check for VID & PID line: "usb 1-1.2: New USB device found, idVendor=0781, idProduct=5581"
            vid_pid_match = cls.VID_PID_PATTERN.search(line)
            if vid_pid_match:
                port_match = re.search(r"usb\s+([0-9\.\-]+):", line)
                port = port_match.group(1) if port_match else "default"
                port_state[port] = {
                    "vid": vid_pid_match.group(1).upper(),
                    "pid": vid_pid_match.group(2).upper(),
                    "serial": None,
                    "product": None,
                    "mfr": None,
                    "first_connected": ts,
                    "last_connected": ts,
                }
                continue

            # Check for SerialNumber line
            serial_match = cls.SERIAL_PATTERN.search(line)
            if serial_match:
                port = serial_match.group(1)
                serial_val = serial_match.group(2).strip()
                if port in port_state:
                    port_state[port]["serial"] = serial_val
                    if ts and not port_state[port]["first_connected"]:
                        port_state[port]["first_connected"] = ts
                    if ts:
                        port_state[port]["last_connected"] = ts
                continue

            # Check for Product line
            prod_match = cls.PRODUCT_PATTERN.search(line)
            if prod_match:
                port = prod_match.group(1)
                if port in port_state:
                    port_state[port]["product"] = prod_match.group(2).strip()
                continue

            # Check for Manufacturer line
            mfr_match = cls.MFR_PATTERN.search(line)
            if mfr_match:
                port = mfr_match.group(1)
                if port in port_state:
                    port_state[port]["mfr"] = mfr_match.group(2).strip()
                continue

            # Check for Disconnect event
            disc_match = cls.DISCONNECT_PATTERN.search(line)
            if disc_match:
                port = disc_match.group(1)
                if port in port_state and ts:
                    port_state[port]["last_connected"] = ts
                continue

            # Check for Volume mount event
            mount_match = cls.MOUNT_PATTERN.search(line)
            if mount_match:
                vol_label = mount_match.group(1).strip()
                # Attach to most recently registered active port state
                for p_data in reversed(list(port_state.values())):
                    if "volume_label" not in p_data or not p_data["volume_label"]:
                        p_data["volume_label"] = vol_label
                        break

        # Consolidate completed port states into devices_by_serial
        for port, info in port_state.items():
            vid = info.get("vid")
            pid = info.get("pid")
            serial = info.get("serial")

            if not vid or not pid:
                continue

            # If serial wasn't explicitly logged, generate fallback pseudo-serial based on port
            if not serial:
                serial = f"LINUX_USB_{vid}_{pid}_{port}"

            # Assemble volume label or product name
            label_parts = []
            if info.get("mfr"):
                label_parts.append(info["mfr"])
            if info.get("product"):
                label_parts.append(info["product"])

            combined_label = " ".join(label_parts).strip() or None
            if info.get("volume_label"):
                combined_label = f"{combined_label} [{info['volume_label']}]" if combined_label else info["volume_label"]

            first_conn = info.get("first_connected")
            last_conn = info.get("last_connected")

            if serial in devices_by_serial:
                existing = devices_by_serial[serial]
                if combined_label and not existing.volume_label:
                    existing.volume_label = combined_label
                if first_conn and (existing.first_connected is None or first_conn < existing.first_connected):
                    existing.first_connected = first_conn
                if last_conn and (existing.last_connected is None or last_conn > existing.last_connected):
                    existing.last_connected = last_conn
            else:
                devices_by_serial[serial] = ParsedUSBDevice(
                    vendor_id=vid,
                    product_id=pid,
                    serial_number=serial,
                    volume_label=combined_label,
                    first_connected=first_conn,
                    last_connected=last_conn,
                )

        return list(devices_by_serial.values())


class USBLogParser:
    """Unified parser router capable of handling Windows SetupAPI and Linux log files."""

    @staticmethod
    def parse_setupapi(content_or_path: Union[str, Path]) -> List[ParsedUSBDevice]:
        """Parses Windows setupapi.dev.log from file path or raw string."""
        if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()):
            text = Path(content_or_path).read_text(encoding="utf-8", errors="replace")
        else:
            text = str(content_or_path)
        return WindowsSetupApiParser.parse(text)

    @staticmethod
    def parse_linux_log(content_or_path: Union[str, Path], default_year: int = 2026) -> List[ParsedUSBDevice]:
        """Parses Linux dmesg or syslog from file path or raw string."""
        if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and "\n" not in content_or_path and Path(content_or_path).is_file()):
            text = Path(content_or_path).read_text(encoding="utf-8", errors="replace")
        else:
            text = str(content_or_path)
        return LinuxUsbLogParser.parse(text, default_year=default_year)

    @classmethod
    def parse_file(cls, filepath: Union[str, Path], default_year: int = 2026) -> List[ParsedUSBDevice]:
        """Auto-detects log format (Windows SetupAPI vs Linux Syslog/dmesg) and extracts USB devices."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        content = path.read_text(encoding="utf-8", errors="replace")
        lower_name = path.name.lower()

        # Heuristic detection based on filename and header content
        if "setupapi" in lower_name or "[Device Install Log]" in content or ">>>  [Device Install" in content:
            return WindowsSetupApiParser.parse(content)
        else:
            return LinuxUsbLogParser.parse(content, default_year=default_year)


# Convenient module-level aliases
parse_setupapi_log = USBLogParser.parse_setupapi
parse_linux_usb_log = USBLogParser.parse_linux_log
