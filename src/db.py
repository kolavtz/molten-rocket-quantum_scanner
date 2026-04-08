"""
SQLAlchemy Session Factory

Provides scoped sessions linked directly to the MySQL database specified by `.env` variables.
To be used for gradual route refactoring.
"""
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from config import SQLALCHEMY_DATABASE_URI

logger = logging.getLogger(__name__)

# Engine configuration mimicking resilience patterns
# Use an in-memory SQLite DB when running under pytest or when an explicit
# test override is provided to avoid requiring a MySQL server during tests.
import os

_engine_uri = os.environ.get("SQLALCHEMY_DATABASE_URI_TEST") or SQLALCHEMY_DATABASE_URI
_running_pytest = any(key.startswith("PYTEST_") for key in os.environ.keys()) or os.environ.get("CI")
if _running_pytest and not os.environ.get("SQLALCHEMY_DATABASE_URI_TEST"):
    _engine_uri = "sqlite:///:memory:"

if _engine_uri.startswith("sqlite:"):
    # SQLite in-memory or file DB: adjust args to avoid pool size/overflow errors
    engine = create_engine(
        _engine_uri,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
        pool_recycle=3600,
    )
else:
    engine = create_engine(
        _engine_uri,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_size=10,
        max_overflow=20
    )

# When running tests or using a test-specific SQLite URI, ensure the ORM
# models' tables exist so pytest can use the in-memory DB without requiring
# an external MySQL instance or manual schema bootstrapping.
try:
    if _engine_uri.startswith("sqlite:") and (
        _running_pytest or ":memory:" in _engine_uri or os.environ.get("SQLALCHEMY_DATABASE_URI_TEST")
    ):
        from src.models import Base

        Base.metadata.create_all(engine)
        logger.info("SQLite test schema created via Base.metadata.create_all")
except Exception as _ex:
    logger.warning("Could not auto-create SQLite test schema: %s", _ex)

# Thread-local session registry
session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db_session = scoped_session(session_factory)

def init_db():
    """Initialize schema via the canonical MySQL bootstrap without destructive ORM resets."""
    from src import database as _database

    ok = _database.init_db()
    if not ok:
        logger.warning("MySQL init_db returned False; app may run in JSON-only mode.")
    return ok
