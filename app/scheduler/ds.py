import base64
import json
import time
import uuid
from io import StringIO
import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, ForeignKey, SmallInteger, select, and_, or_, \
    func, delete
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from app.systems.config import AppConfig
from app.systems.logging import logger, s_id_ctx_var
from app.systems.database import get_db, Base
from app.ds import DSHook

from app.main import scheduler


# Шаблон таблицы
class Tasker(Base):
    __tablename__ = "ds_tasker"

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


def decode_param(param):
    param = base64.b64decode(param.encode('utf-8'))

    param = AppConfig.SECRET_KEY.decrypt(
        param,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return json.loads(param.decode('utf-8'))


async def run_execution():
    # Создание строки сессии
    s_id_ctx_var.set(str(uuid.uuid4()))

    async for db in get_db():
        while True:
            result = await db.execute(select(Tasker).where(
                (Tasker.status == 'waiting')
            ))
            task = result.scalars().first()

            status = None
            result = None

            if task:
                try:
                    type_query = str(task.type_query)
                    param_conn = decode_param(task.param_conn)
                    param_query = decode_param(task.param_query)

                    with DSHook(**param_conn) as ds:
                        result = getattr(ds, type_query)(**param_query)

                    status = 'complete'
                except Exception as e:
                    status = 'error'
                    result = {'error': str(e)}
                finally:
                    task.status = status
                    task.result = result
                    await db.commit()
            else:
                logger.info("NOT FOUND QUERY")
                break


scheduler.add_job(run_execution, "interval", minutes=1, id="ds_tasker")


async def run_cleaning():
    # Создание строки сессии
    s_id_ctx_var.set(str(uuid.uuid4()))

    async for db in get_db():
        await db.execute(delete(Tasker).where(Tasker.created_at < func.now() - timedelta(hours=1)))
        await db.commit()


scheduler.add_job(run_cleaning, "interval", minutes=60, id="ds_tasker_cleaning")
