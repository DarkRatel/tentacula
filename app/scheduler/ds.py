import json
import uuid
import base64
from datetime import datetime, timezone, timedelta

import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from sqlalchemy import Column, Integer, String, DateTime, JSON, select, func, delete

from app.sds import SDSHook
from app.systems.config import AppConfig
from app.systems.logging import logger, s_id_ctx_var
from app.systems.database import Base
from app.moduls.json_encoder import json_encoder
from app.systems.database import AsyncSessionLocal
from app.main import scheduler

# Переменная для отслеживания заданий работающих в фоновом режиме
background_tasks: set[asyncio.Task] = set()


def track_background_task(task: asyncio.Task) -> None:
    """Отслеживания задания"""
    background_tasks.add(task)

    def _done_callback(t: asyncio.Task):
        background_tasks.discard(t)

        try:
            t.result()
        except asyncio.CancelledError:
            logger.warning("Background task was cancelled")
        except Exception:
            logger.exception("Background task failed")

    task.add_done_callback(_done_callback)


# Шаблон таблицы
class Tasker(Base):
    __tablename__ = "tentacula_ds_tasker"

    id = Column(Integer, primary_key=True, index=True)
    status = Column(String, nullable=False)
    type_query = Column(String, nullable=False)
    param_conn = Column(String, nullable=False)
    param_query = Column(String, nullable=False)
    result = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False,
                        server_default=func.now())
    update_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False,
                       onupdate=datetime.now(timezone.utc), server_default=func.now())


def decode_param(param) -> dict:
    """Функция расшифровки данных полученных из таблицы, с использованием закрытого ключа"""
    param = base64.b64decode(param.encode('utf-8'))

    key_len = int.from_bytes(param[:4], "big")
    offset = 4

    encrypted_aes_key = param[offset:offset + key_len]
    offset += key_len

    nonce = param[offset:offset + 12]
    ciphertext = param[offset + 12:]

    # Расшифровка AES-ключа
    aes_key = AppConfig.APP__SECRET_KEY.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Расшифровка текста
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode('utf-8'))


def run_ds(uuid_session, type_query, param_conn, param_query):
    """Функция исполнения запроса к СК"""
    s_id_ctx_var.set(uuid_session)
    with SDSHook(**param_conn) as ds:
        result = getattr(ds, type_query)(**param_query)
        return result


async def task_processing(source_uuid: str, task_id: int):
    """Функция исполнения выбранного задания. В ID события добавляется ID строки из таблицы заданий"""
    uuid_session = f"{source_uuid}-{task_id}"
    s_id_ctx_var.set(uuid_session)

    logger.info(f"====Start task id: %s====", task_id)

    # Подключение к БД
    async with AsyncSessionLocal() as db:
        try:
            task = (
                await db.execute(select(Tasker).where(Tasker.id == task_id))
            ).scalar_one()
            task.status = "working"
            await db.commit()

            type_query = str(task.type_query)
            param_conn = decode_param(task.param_conn)
            param_query = decode_param(task.param_query)

            logger.info('Original Query: %s, Param Connect: %s, Param Query: %s',
                        type_query, param_conn, param_query)

            # Изменение входных параметров, если такое описано в TRANSIT
            # Данные пришедшие в задание из таблицы более приоритетные
            if param_conn['host'] in AppConfig.SCHEDULERS_DS__TRANSIT:
                transit = AppConfig.SCHEDULERS_DS__TRANSIT[param_conn['host']]
                param_conn['host'] = transit['host']
                param_conn = transit | param_conn

                logger.info('Transit Param Connect: %s', param_conn)

            # Исполнение запроса
            result = await asyncio.to_thread(
                run_ds,
                uuid_session, type_query, param_conn, param_query
            )

            task.result = json_encoder(result)
            task.status = 'complete'
            await db.commit()
        except Exception as e:
            e = str(e)
            logger.info(f"Error : %s", e)

            async with AsyncSessionLocal() as db:
                task = (
                    await db.execute(select(Tasker).where(Tasker.id == task_id))
                ).scalar_one()

                task.status = 'error'
                task.result = e
                await db.commit()

            logger.info(f"====End====")

            raise

        logger.info(f"====End====")


async def scheduler_ds_tasker():
    """Функция поиска заданий в таблице и создания отдельного события для каждого задания"""
    # Создание строки сессии
    source_uuid = str(uuid.uuid4())
    s_id_ctx_var.set(source_uuid)

    logger.info("Active background tasks: %s", len(background_tasks))

    async with AsyncSessionLocal() as db:
        # Запрос всех заданий в статусе ожидающих обработку
        result = await db.execute(select(Tasker).where(
            (Tasker.status == 'waiting')
        ))
        tasks = result.scalars().all()

        if not tasks:
            logger.info("Not found new tasks in DB")
            return

        # Изменение статуса для взрытых в работу
        for task in tasks:
            task.status = "in_line"
        await db.commit()

        task_ids = [task.id for task in tasks]

        logger.info(f"New tasks id for run: %s", task_ids)

    # Для всех найденных заданий формирование задания для исполнения на заднем фоне
    for task_id in task_ids:
        bg_task = asyncio.create_task(task_processing(source_uuid, task_id))
        track_background_task(bg_task)


# Запуск заданий для обращения к СК
scheduler.add_job(scheduler_ds_tasker, "interval", minutes=1, id="scheduler_ds_tasker",
                  max_instances=1, coalesce=True)


async def scheduler_ds_cleaning():
    """Функция очистки таблицы от неактуальных заданий"""
    # Создание строки сессии
    s_id_ctx_var.set(str(uuid.uuid4()))

    async with AsyncSessionLocal() as db:
        await db.execute(delete(Tasker).where(Tasker.created_at < func.now() - timedelta(hours=1)))
        await db.commit()

# Запуск удаления неиспользованных заданий
scheduler.add_job(scheduler_ds_cleaning, "interval", minutes=60, id="scheduler_ds_cleaning",
                  max_instances=1, coalesce=True)
