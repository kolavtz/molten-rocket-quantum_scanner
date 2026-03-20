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
    """Generates all unified models onto the active MySQL connection."""
    import src.models
    try:
        # Drop legacy mismatched tables first
        src.models.Base.metadata.drop_all(bind=engine)
        src.models.Base.metadata.create_all(bind=engine)
        logger.info("SQLAlchemy ORM Metadata synchronised to MySQL successfully.")
    except Exception as e:
        logger.error(f"Failed to synchronize ORM metadata: {e}")
        raise
