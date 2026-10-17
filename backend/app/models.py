from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Boolean,
    Text,
    ForeignKey
)
from sqlalchemy.orm import relationship
from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Device(Base):
    """Represents a connected or parsed USB hardware device artifact."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    vendor_id = Column(String(32), nullable=False, index=True)
    product_id = Column(String(32), nullable=False, index=True)
    serial_number = Column(String(128), nullable=False, unique=True, index=True)
    volume_label = Column(String(128), nullable=True)
    first_connected = Column(DateTime, nullable=True, default=utcnow)
    last_connected = Column(DateTime, nullable=True, default=utcnow)

    # Relationships
    file_artifacts = relationship(
        "FileArtifact",
        back_populates="device",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Device(id={self.id}, VID={self.vendor_id}, PID={self.product_id}, SN={self.serial_number})>"


class FileArtifact(Base):
    """Represents a file metadata artifact extracted from a USB volume or inspection."""
    __tablename__ = "file_artifacts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    file_path = Column(String(1024), nullable=False)
    file_size = Column(Integer, nullable=False, default=0)  # size in bytes
    creation_time = Column(DateTime, nullable=True)
    modification_time = Column(DateTime, nullable=True)
    md5_hash = Column(String(32), nullable=True, index=True)
    sha256_hash = Column(String(64), nullable=True, index=True)
    flag_suspicious = Column(Boolean, nullable=False, default=False, index=True)
    flag_reason = Column(Text, nullable=True)

    # Relationships
    device = relationship("Device", back_populates="file_artifacts")

    def __repr__(self) -> str:
        return f"<FileArtifact(id={self.id}, path={self.file_path}, suspicious={self.flag_suspicious})>"
