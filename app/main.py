import os
import importlib

from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from jinja2 import Template

from app.systems.config import AppConfig
from app.systems.logging import logger, s_id_ctx_var, setup_logging

# Настройка root'ового logging, для перехвата всех данных выводимых в логгер
setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"COMPOSITION_ENABLED: {AppConfig.COMPOSITION_ENABLED}")
    logger.info(f"    SUCKERS_ENABLED: {AppConfig.SUCKERS_ENABLED}")
    logger.info(f"         SUCKERS_DS: {AppConfig.SUCKERS_DS}")
    logger.info(f" SCHEDULERS_ENABLED: {AppConfig.SCHEDULERS_ENABLED}")
    logger.info(f"      SCHEDULERS_DS: {AppConfig.SCHEDULERS_DS}")

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

    yield


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
