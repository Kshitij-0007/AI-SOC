from __future__ import annotations
import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from .models import Base

def get_session_factory(config: dict | None = None) -> sessionmaker[Session]:
    cfg = (config or {}).get("database", {})
    url = os.getenv(cfg.get("url_env", "DATABASE_URL"))
    if not url:
        database = Path(__file__).resolve().parents[2] / cfg.get("sqlite_path", "data/ai_soc.db")
        url = f"sqlite:///{database.resolve().as_posix()}"
    options = {"connect_args": {"check_same_thread": False, "timeout": 30.0}} if url.startswith("sqlite") else {}
    engine = create_engine(url, future=True, **options)
    if url.startswith("sqlite"):
        from sqlalchemy import event
        @event.listens_for(engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA busy_timeout=30000")
            except Exception:
                pass
            finally:
                cursor.close()
    return sessionmaker(bind=engine, expire_on_commit=False)

def create_schema(config: dict | None = None) -> None:
    Base.metadata.create_all(get_session_factory(config).kw["bind"])
