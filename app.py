import os
import importlib

from fastapi import FastAPI
from sites.suckers import router_sucker
from sites.composition import router_composition
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from contextlib import asynccontextmanager

from systems.logging import logger
from systems.config import AppConfig
from systems.database import engine, Base


if AppConfig.SCHEDULERS_ENABLED:
    scheduler = AsyncIOScheduler()

    # Импорт всех дополнительных путей связанных с присосками
    for filename in os.listdir(AppConfig.SCHEDULERS_FOLDER):
        if filename.endswith(".py") and filename != "__init__.py":
            importlib.import_module(f"{AppConfig.SCHEDULERS_FOLDER}.{filename[:-3]}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"SUCKERS_ENABLED: {AppConfig.SUCKERS_ENABLED}")
    logger.info(f"SCHEDULERS_ENABLED: {AppConfig.SCHEDULERS_ENABLED}")

    if AppConfig.SCHEDULERS_ENABLED:
        logger.info("Run scheduler...")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        scheduler.start()
        yield  # Запуск самого FastAPI
        logger.info("...stop scheduler")
        scheduler.shutdown()
    else:
        yield  # Запуск самого FastAPI


app = FastAPI(lifespan=lifespan)


app.include_router(router_sucker)
app.include_router(router_composition)

# Альтернативный запуск uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        app_dir='/app',
        host="0.0.0.0",
        port=5001,
        reload=True,
        ssl_certfile="./certs/cert.pem",
        ssl_keyfile="./certs/key.pem"
    )
