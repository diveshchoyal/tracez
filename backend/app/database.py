"""TraceZ Backend — Database Configuration and Models."""

import json
from datetime import datetime, timezone
from typing import Generator
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from app.config import settings

# Create engine and session maker
engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Models ---

class User(Base):
    """User accounts (Admins and Standard Extension Users)."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    api_key = Column(String, unique=True, index=True, nullable=True)
    is_active = Column(Boolean, default=True)
    role = Column(String, default="USER")  # "USER" or "ADMIN"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship("ScanLog", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class ScanLog(Base):
    """Logs of scanned URLs and files."""
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True, nullable=False)
    verdict = Column(String, nullable=False)  # "SAFE", "SUSPICIOUS", "DANGEROUS"
    risk_score = Column(Integer, nullable=False)  # 0 to 100
    scan_time_ms = Column(Integer, default=0)
    signals_json = Column(Text, default="[]")  # Serialized signals list
    reputation_json = Column(Text, default="{}")  # Serialized external reputational findings
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="scans")

    @property
    def signals(self):
        try:
            return json.loads(self.signals_json)
        except Exception:
            return []

    @signals.setter
    def signals(self, value):
        self.signals_json = json.dumps(value)

    @property
    def reputation(self):
        try:
            return json.loads(self.reputation_json)
        except Exception:
            return {}

    @reputation.setter
    def reputation(self, value):
        self.reputation_json = json.dumps(value)


class BlocklistEntry(Base):
    """Local threat feeds compiled blocklist entries."""
    __tablename__ = "blocklist_entries"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    category = Column(String, default="phishing")  # "phishing", "malware", "scam"
    source = Column(String, default="local")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    """Security audit records for user/admin state-changing actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)  # e.g., "admin_login", "blocklist_update"
    ip_address = Column(String, nullable=True)
    details = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="audit_logs")


class ThreatFeed(Base):
    """External threat intelligence feeds configured for ingestion."""
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    url = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    last_sync_status = Column(String, nullable=True)
    last_sync_time = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Threat(Base):
    """TRZ Threat Signatures Registry."""
    __tablename__ = "trz_threats"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, index=True)
    category = Column(String, index=True)  # APK, LIB, URL, NET
    severity = Column(String, default="DANGEROUS")  # SAFE, SUSPICIOUS, DANGEROUS
    description = Column(Text)
    verdict_text = Column(Text)
    features_json = Column(Text)


class Scan(Base):
    """TRZ File/URL Scan Reports."""
    __tablename__ = "trz_scans"

    id = Column(String, primary_key=True, index=True)
    filename = Column(String)
    type = Column(String)  # FILE, URL
    verdict = Column(String)  # SAFE, SUSPICIOUS, DANGEROUS
    risk_score = Column(Integer)
    layer_results = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# --- Database Helpers ---

def get_db() -> Generator[Session, None, None]:
    """FastAPI database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create tables and seed initial admin user if not exists."""
    Base.metadata.create_all(bind=engine)
    
    # Check if admin user exists, if not seed them
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if not admin:
            # We defer import of hash_password to prevent circular imports
            from app.utils.crypto import hash_password, generate_api_key
            
            admin_user = User(
                email=settings.ADMIN_EMAIL,
                hashed_password=hash_password(settings.ADMIN_PASSWORD),
                api_key=generate_api_key(),
                role="ADMIN",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            print(f"[*] Default admin seeded: {settings.ADMIN_EMAIL}")
            
            # Seed default threat feeds
            default_feeds = [
                ("PhishTank", "https://data.phishtank.com/data/online-valid.json"),
                ("URLhaus", "https://urlhaus.abuse.ch/downloads/json/")
            ]
            for name, feed_url in default_feeds:
                if not db.query(ThreatFeed).filter(ThreatFeed.name == name).first():
                    feed = ThreatFeed(name=name, url=feed_url, is_active=True)
                    db.add(feed)
            db.commit()
            # Seed default threats
            if db.query(Threat).count() == 0:
                default_threats = [
                    Threat(
                        id="TRZ-LIB-a3f2c9d84e11",
                        name="XLoader Spyware SDK",
                        category="LIB",
                        severity="DANGEROUS",
                        description="Malicious spy library specializing in SMS exfiltration, background recording, and contacts harvesting.",
                        verdict_text="This app contains XLoader spyware. It intercepts incoming text messages and records microphone input without notification.",
                        features_json=json.dumps([
                            "permission:READ_SMS", "permission:SEND_SMS", "permission:INTERNET",
                            "api:SmsManager.sendTextMessage", "api:AudioRecord.startRecording",
                            "namespace:com.xloader.sdk"
                        ])
                    ),
                    Threat(
                        id="TRZ-LIB-b5828d11ef83",
                        name="SpyNote Surveillance",
                        category="LIB",
                        severity="DANGEROUS",
                        description="Remote Access Trojan (RAT) SDK allowing remote controls, shell execution, and keylogging.",
                        verdict_text="Detected SpyNote RAT hooks. This app allows external attackers to control your device, execute shell commands, and read keypresses.",
                        features_json=json.dumps([
                            "permission:RECORD_AUDIO", "permission:WRITE_EXTERNAL_STORAGE",
                            "permission:RECEIVE_BOOT_COMPLETED", "api:Runtime.getRuntime.exec",
                            "namespace:io.spynote.client"
                        ])
                    ),
                    Threat(
                        id="TRZ-LIB-c191a82f33b1",
                        name="Firebase Stalkerware Tracker",
                        category="LIB",
                        severity="SUSPICIOUS",
                        description="Suspicious configuration tracking call histories and address books, transmitting them to Firebase endpoints.",
                        verdict_text="Identified stalkerware-like telemetry. The app copies call history details and updates them silently to an online cloud.",
                        features_json=json.dumps([
                            "permission:READ_CONTACTS", "permission:READ_CALL_LOG", "permission:INTERNET",
                            "namespace:com.google.firebase"
                        ])
                    ),
                    Threat(
                        id="TRZ-URL-d2382f1bc8f8",
                        name="Amazon Prize Phishing Page",
                        category="URL",
                        severity="DANGEROUS",
                        description="Phishing portal mimicking amazon.com to harvest credit card credentials.",
                        verdict_text="This page is a confirmed fake Amazon login trying to steal payment details. Do not enter credentials.",
                        features_json=json.dumps([
                            "redirects:true", "typosquat:amazon", "age:under_7_days"
                        ])
                    ),
                    Threat(
                        id="TRZ-URL-e923831fdcc9",
                        name="WhatsApp Mod Adware Host",
                        category="NET",
                        severity="SUSPICIOUS",
                        description="Malicious distribution server serving WhatsApp Mods packed with background adware code.",
                        verdict_text="Known adware hosting domain. Files downloaded from here display system-wide intrusive banner ads.",
                        features_json=json.dumps([
                            "ip:185.220.101.45", "download:apk", "cert:self_signed"
                        ])
                    )
                ]
                db.bulk_save_objects(default_threats)
                db.commit()
                print("[*] Default TRZ threats seeded in database.")
    except Exception as e:
        print(f"[!] Error seeding database: {e}")
        db.rollback()
    finally:
        db.close()
