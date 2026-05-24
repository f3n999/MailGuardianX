"""
Gestionnaire de session SQLAlchemy 2.0 async (asyncpg).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine,
)

from orchestrator.core.config import get_settings

logger = logging.getLogger(__name__)


_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


def _normalize_url(url: str) -> str:
    """Force le driver asyncpg si l'URL utilise postgresql:// sans driver."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def init_engine() -> AsyncEngine:
    """Initialise l'engine + sessionmaker (idempotent)."""
    global _engine, _sessionmaker
    if _engine is not None:
        return _engine

    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError("DATABASE_URL non configuré — impossible d'initialiser la DB.")

    url = _normalize_url(settings.database_url)
    _engine = create_async_engine(
        url,
        echo=settings.debug,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_recycle=3600,
    )
    _sessionmaker = async_sessionmaker(
        _engine, expire_on_commit=False, class_=AsyncSession,
    )
    logger.info("DB engine initialisé (driver: asyncpg)")
    return _engine


async def dispose_engine() -> None:
    """Ferme l'engine au shutdown."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
        logger.info("DB engine fermé")


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """
    Context manager pour une session DB transactionnelle.

    Usage:
        async with session_scope() as db:
            db.add(obj)
            # commit auto en sortie, rollback si exception
    """
    if _sessionmaker is None:
        init_engine()
    assert _sessionmaker is not None
    async with _sessionmaker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_session() -> AsyncIterator[AsyncSession]:
    """
    Dépendance FastAPI : injecte une session par requête.

    Usage:
        @router.get("/")
        async def endpoint(db: AsyncSession = Depends(get_session)):
            ...
    """
    async with session_scope() as session:
        yield session
