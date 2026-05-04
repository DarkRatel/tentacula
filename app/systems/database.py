import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from app.systems.config import AppConfig

# Игнорирование событий от sqlalchemy, связанных с запросом в БД, так как в них нет подходящих данных
logging.getLogger("sqlalchemy.engine.Engine").setLevel(logging.WARNING)

# Создание асинхронного движка базы данных
engine = create_async_engine(AppConfig.APP__DB_ASYNC_URL, echo=False, future=True)

# Фабрика сессий
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False
)


# Функция для получения сессии
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


# Базовый класс моделей
Base = declarative_base()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
