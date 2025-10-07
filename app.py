import os
import importlib

import uvicorn
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
    # NGINX_DEFAULT = "/nginx/default.conf"
    # NGINX_J2_HTTP = "/nginx/default.conf.http.j2"
    # NGINX_J2_HTTPS = "/nginx/default.conf.https.j2"
    #
    # from jinja2 import Template
    # from pathlib import Path
    # import socket

    # logger.info(f"Generate NGINX Config...")
    #
    # template_file =  NGINX_J2_HTTPS if AppConfig.USE_SSL else NGINX_J2_HTTP
    #
    # with open(template_file) as f:
    #     template = Template(f.read())
    #
    # conf = Template(template).render(
    #     uvicorn_host_name=socket.gethostname(),
    #     uvicorn_port=AppConfig.PORT
    # )
    #
    # with open(NGINX_DEFAULT, "w") as f:
    #     f.write(conf)
    #
    # logger.info(f"...Done")

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
importlib.import_module("sites.root")

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        app_dir='/app',
        host="0.0.0.0",
        port=AppConfig.PORT,
        reload=AppConfig.RELOAD,
        proxy_headers=True,
    )
