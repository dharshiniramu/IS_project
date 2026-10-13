from fastapi import HTTPException, status
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


def create_database_engine() -> Engine | None:
    mysql_url = get_settings().mysql_url
    return create_engine(mysql_url, pool_pre_ping=True, pool_recycle=3600) if mysql_url else None


engine = create_database_engine()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False) if engine is not None else None


def check_database_connection() -> bool:
    if engine is None:
        return False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        return False


def init_db() -> None:
    if engine is not None:
        Base.metadata.create_all(bind=engine)


def get_db():
    if SessionLocal is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is not configured. Create backend/.env and set MYSQL_URL.",
        )
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
