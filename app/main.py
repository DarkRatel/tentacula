import os
import importlib

from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from jinja2 import Template
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.systems.config import AppConfig
from app.systems.logging import logger, s_id_ctx_var, setup_logging

# Настройка root'ового logging, для перехвата всех данных выводимых в логгер
setup_logging()

if any([AppConfig.SCHEDULERS_ENABLED, AppConfig.SCHEDULERS_DS]):
    scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"COMPOSITION_ENABLED: {AppConfig.COMPOSITION_ENABLED}")
    logger.info(f"    SUCKERS_ENABLED: {AppConfig.SUCKERS_ENABLED}")
    logger.info(f"         SUCKERS_DS: {AppConfig.SUCKERS_DS}")
    logger.info(f" SCHEDULERS_ENABLED: {AppConfig.SCHEDULERS_ENABLED}")
    logger.info(f"      SCHEDULERS_DS: {AppConfig.SCHEDULERS_DS}")

    # Блок настройки NGINX-файла
    if AppConfig.NGINX_FILE:
        logger.info(f"Generate NGINX Conf: {AppConfig.NGINX_FILE}")

        with open(f"{os.getcwd()}/app/nginx/nginx.conf.j2", "r") as f:
            template = Template(f.read()).render(
                folder_logs=AppConfig.NGINX_FOLDER_LOGS,
                port=AppConfig.PORT,
                ssl_certfile=AppConfig.SSL_CERTFILE,
                ssl_keyfile=AppConfig.SSL_KEYFILE,
                ssl_ca_certs=AppConfig.SSL_CA_CERTS,
            )

        with open(AppConfig.NGINX_FILE, "w") as f:
            f.write(template)

        logger.info(f"Generate Done")
    else:
        logger.info(f"Skip Generate NGINX Conf")

    # Блок включения приложения

    # Если шедуллер активен
    if AppConfig.SCHEDULERS_ENABLED or AppConfig.SCHEDULERS_DS:

        if AppConfig.SCHEDULERS_DS:
            from app.systems.database import init_db

            logger.info("Generate table for SCHEDULERS_DS")
            await init_db()

        logger.info("Run scheduler...")
        scheduler.start()
        yield  # Запуск самого FastAPI
        logger.info("...stop scheduler")
        scheduler.shutdown()
    # Запуск без шедуллера
    else:
        yield  # Запуск самого FastAPI


app = FastAPI(lifespan=lifespan)


@app.middleware("http")
async def system_middleware(request: Request, call_next):
    # Сохранение уникального кода сессии в контекст, для добавления в логи
    s_id_ctx_var.set(request.headers["x-request-id"])
    response = await call_next(request)
    return response


# Импорт первой страницы приложения
importlib.import_module("app.sites.root")

# Импорт пользовательских щупалец, если включено
if AppConfig.SUCKERS_ENABLED:
    from app.sites.suckers import router_sucker

    app.include_router(router_sucker)

# Импорт щупалец связанных с DS, если включено
if AppConfig.SUCKERS_DS:
    from app.sites.ds import router_ds

    for i in ["add_group_member", "get_computer", "get_contact", "get_group", "get_group_member", "get_object",
              "get_user", "move_object", "new_contact", "new_group", "new_user", "remove_computer", "remove_contact",
              "remove_group", "remove_group_member", "remove_object", "remove_user", "rename_object",
              "set_account_password", "set_account_unlock", "set_computer", "set_contact", "set_group", "set_object",
              "set_user"]:
        importlib.import_module(f"app.sites.ds.{i}")

    app.include_router(router_ds)

# Импорт шеделлера для работы с DS, если включен
if AppConfig.SCHEDULERS_DS:
    importlib.import_module(f"app.scheduler.ds")
