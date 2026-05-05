import os
import sys
import importlib

from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from jinja2 import Template
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.systems.config import AppConfig
from app.systems.logging import logger, s_id_ctx_var, setup_logging

# Настройка root'ового logging, для перехвата всех данных выводимых в логгер
setup_logging()

# Если в конфигурации есть запуск SCHEDULERS, то инициализируется приложение
if any([AppConfig.SCHEDULERS__ENABLED, AppConfig.SCHEDULERS_DS__ENABLED]):
    scheduler = AsyncIOScheduler(
        timezone="UTC",
        job_defaults={
            "misfire_grace_time": 15,  # Разрешение запускать задачу, если прошло больше 15 секунд с планового запуска
            "coalesce": True,  # Если есть накопленные задания, исполнять только 1
            "max_instances": 1,  # Запускать параллельно только 1 копию задания
        },
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"  COMPOSITION__ENABLED: {AppConfig.COMPOSITION__ENABLED}")
    logger.info(f"      SUCKERS__ENABLED: {AppConfig.SUCKERS__ENABLED}")
    logger.info(f"   SUCKERS_DS__ENABLED: {AppConfig.SUCKERS_DS__ENABLED}")
    logger.info(f"   SCHEDULERS__ENABLED: {AppConfig.SCHEDULERS__ENABLED}")
    logger.info(f"SCHEDULERS_DS__ENABLED: {AppConfig.SCHEDULERS_DS__ENABLED}")

    # Блок настройки NGINX-файла
    if AppConfig.WEB__NGINX_FILE:
        logger.info(f"Generate NGINX Conf: {AppConfig.WEB__NGINX_FILE}")

        if AppConfig.WEB__SSL_ENABLED:
            with open(f"{os.getcwd()}/app/nginx/nginx_ssl.conf.j2", "r") as f:
                template = Template(f.read()).render(
                    folder_logs=AppConfig.WEB__LOGS_FOLDER,
                    port=AppConfig.WEB__PORT,
                    ssl_certfile=AppConfig.WEB__SSL_CERTFILE,
                    ssl_keyfile=AppConfig.WEB__SSL_KEYFILE,
                    ssl_ca_certs=AppConfig.WEB__SSL_CA_CERTS,
                )
        else:
            with open(f"{os.getcwd()}/app/nginx/nginx_nossl.conf.j2", "r") as f:
                template = Template(f.read()).render(
                    folder_logs=AppConfig.WEB__LOGS_FOLDER,
                    port=AppConfig.WEB__PORT,
                )

        with open(AppConfig.WEB__NGINX_FILE, "w") as f:
            f.write(template)

        logger.info(f"Generate Done")
    else:
        logger.info(f"Skip Generate NGINX Conf")

    # Блок включения приложения

    # Если шедуллер активен
    if any([AppConfig.SCHEDULERS__ENABLED, AppConfig.SCHEDULERS_DS__ENABLED]):

        # Если указана строка подключения к БД и включен SCHEDULERS_DS__ENABLED
        if AppConfig.SCHEDULERS_DS__ENABLED and AppConfig.APP__DB_ASYNC_URL:
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

    logger.info(f"Protocol: {request.headers['x-forwarded-proto'].upper()}, "
                f"Host name: {request.headers['host']}, "
                f"Host ip: {request.headers['x-server-ip']}, "
                f"URL: {request.url}, "
                f"Client ip: {request.headers.get('x-forwarded-for')}")

    return response


# Импорт первой страницы приложения
from app.sites.root import router_root

app.include_router(router_root)

# Импорт пользовательских щупалец, если включено
if AppConfig.SUCKERS__ENABLED:
    from app.sites.suckers import router_sucker

    app.include_router(router_sucker)

# Импорт щупалец связанных с DS, если включено
if AppConfig.SUCKERS_DS__ENABLED:
    from app.sites.ds import router_ds

    for i in ["add_group_member", "get_computer", "get_contact", "get_group", "get_group_member", "get_object",
              "get_user", "move_object", "new_contact", "new_group", "new_user", "remove_computer", "remove_contact",
              "remove_group", "remove_group_member", "remove_object", "remove_user", "rename_object",
              "set_account_password", "set_account_unlock", "set_computer", "set_contact", "set_group", "set_object",
              "set_user"]:
        importlib.import_module(f"app.sites.ds.{i}")

    app.include_router(router_ds)

# Импорт сочленения для работы с DS, если включен
if AppConfig.COMPOSITION__ENABLED:
    from app.sites.composition import router_composition

    app.include_router(router_composition)

# Импорт пользовательских шедуллеров
if AppConfig.SCHEDULERS__ENABLED:
    import importlib.util
    from pathlib import Path

    shed_dir = Path(AppConfig.SCHEDULERS__FOLDER)

    for module_path in shed_dir.glob("*.py"):
        if module_path.name == "__init__.py":
            continue

        module_name = f"app.scheduler.{module_path.stem}"

        spec = importlib.util.spec_from_file_location(module_name, module_path)

        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module from {module_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        register_jobs = getattr(module, "register_jobs", None)
        if callable(register_jobs):
            register_jobs(scheduler)

# Импорт шедуллера для работы с DS, если включен
if AppConfig.SCHEDULERS_DS__ENABLED:
    importlib.import_module(f"app.scheduler.ds")
