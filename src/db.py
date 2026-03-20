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
engine = create_engine(
    SQLALCHEMY_DATABASE_URI,
    pool_pre_ping=True,
    pool_recycle=3600,
    pool_size=10,
    max_overflow=20
)

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
