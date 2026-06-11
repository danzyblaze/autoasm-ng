"""SQLAlchemy ORM models — the persistence layer (Chapter 3, §3.4.1 ER diagram).

Entities: Organisation, Asset, Exposure, Correlation, RiskScore, Scan.
"""
from __future__ import annotations

import datetime as _dt
from typing import Optional

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Integer, String,
                        Text, create_engine)
from sqlalchemy.orm import (DeclarativeBase, Mapped, mapped_column, relationship,
                            sessionmaker)

from .config import DB_URL


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class Organisation(Base):
    __tablename__ = "organisation"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    root_domains: Mapped[str] = mapped_column(Text, default="")   # comma-separated
    default_criticality: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow)

    assets: Mapped[list["Asset"]] = relationship(back_populates="org",
                                                 cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="org",
                                               cascade="all, delete-orphan")

    def domain_list(self) -> list[str]:
        return [d.strip() for d in self.root_domains.split(",") if d.strip()]


class Asset(Base):
    __tablename__ = "asset"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organisation.id"), index=True)
    type: Mapped[str] = mapped_column(String(20))   # subdomain|ip|bucket|endpoint|service
    value: Mapped[str] = mapped_column(String(512), index=True)
    source: Mapped[str] = mapped_column(String(64), default="")
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    first_seen: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow)
    last_seen: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow)

    org: Mapped["Organisation"] = relationship(back_populates="assets")
    exposures: Mapped[list["Exposure"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan")


class Exposure(Base):
    __tablename__ = "exposure"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    cls: Mapped[str] = mapped_column("class", String(64))   # exposure class
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_ref: Mapped[str] = mapped_column(Text, default="")
    cvss_base: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(20), default="open")
    detected_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow)

    asset: Mapped["Asset"] = relationship(back_populates="exposures")
    correlations: Mapped[list["Correlation"]] = relationship(
        back_populates="exposure", cascade="all, delete-orphan")
    risk: Mapped[Optional["RiskScore"]] = relationship(
        back_populates="exposure", uselist=False, cascade="all, delete-orphan")


class Correlation(Base):
    __tablename__ = "correlation"
    id: Mapped[int] = mapped_column(primary_key=True)
    exposure_id: Mapped[int] = mapped_column(ForeignKey("exposure.id"), index=True)
    source: Mapped[str] = mapped_column(String(20))   # NVD|KEV|HIBP|CORPUS
    cve_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    kev_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    epss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    breach_tag: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    weight: Mapped[float] = mapped_column(Float, default=0.0)

    exposure: Mapped["Exposure"] = relationship(back_populates="correlations")


class RiskScore(Base):
    __tablename__ = "risk_score"
    exposure_id: Mapped[int] = mapped_column(ForeignKey("exposure.id"),
                                             primary_key=True)
    criticality: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[float] = mapped_column(Float, default=0.0)
    breach_relevance: Mapped[float] = mapped_column(Float, default=1.0)
    composite_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    rank: Mapped[int] = mapped_column(Integer, default=0)
    computed_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow)

    exposure: Mapped["Exposure"] = relationship(back_populates="risk")


class Scan(Base):
    __tablename__ = "scan"
    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organisation.id"), index=True)
    started_at: Mapped[_dt.datetime] = mapped_column(DateTime, default=_utcnow)
    finished_at: Mapped[Optional[_dt.datetime]] = mapped_column(DateTime,
                                                               nullable=True)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    exposure_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    notes: Mapped[str] = mapped_column(Text, default="")

    org: Mapped["Organisation"] = relationship(back_populates="scans")


# --- Engine / session factory ---------------------------------------------
# SQLite needs check_same_thread=False because scan jobs run in background
# threads. WAL mode lets the web request thread read while a scan writes.
if DB_URL.startswith("sqlite"):
    _engine = create_engine(DB_URL, future=True,
                            connect_args={"check_same_thread": False})

    from sqlalchemy import event

    @event.listens_for(_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _rec):  # pragma: no cover
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=10000")
        cur.close()
else:
    _engine = create_engine(DB_URL, future=True, pool_pre_ping=True)

SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)


def init_db() -> None:
    """Create all tables if they do not exist."""
    Base.metadata.create_all(_engine)


def get_session():
    return SessionLocal()
