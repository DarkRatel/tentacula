import json
import uuid
import base64
import httpx, ssl
from functools import reduce
from datetime import datetime, timezone, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from sqlalchemy import Column, Integer, String, DateTime, Boolean, JSON, ForeignKey, SmallInteger, select, and_, or_, \
    func, delete

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


def decode_param(param) -> dict:
    param = base64.b64decode(param.encode('utf-8'))

    key_len = int.from_bytes(param[:4], "big")
    offset = 4

    encrypted_aes_key = param[offset:offset + key_len]
    offset += key_len

    nonce = param[offset:offset + 12]
    ciphertext = param[offset + 12:]

    # Расшифровка AES-ключа
    aes_key = AppConfig.SECRET_KEY.decrypt(
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

                    logger.info(param_conn)
                    logger.info(param_query)

                    transit = AppConfig.TRANSIT.get(param_conn['host'])
                    if transit:
                        logger.info('Transit %s', param_conn['host'])

                        ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=transit['SSL_CA_CERTS'])
                        ssl_ctx.load_cert_chain(certfile=transit['SSL_CERTFILE'], keyfile=transit['SSL_KEYFILE'])
                        transport = httpx.HTTPTransport(verify=ssl_ctx)
                        timeout = httpx.Timeout(connect=900, read=900, write=900, pool=900)
                        client = httpx.Client(transport=transport, timeout=timeout)

                        param_conn['host'] = transit['HOST']

                        url = f"{transit['ADDRESS']}/ds/{type_query}"
                        logger.info("POST: %s", url)

                        response = client.post(
                            url,
                            json={**param_conn, **param_conn},
                        )
                        response.raise_for_status()

                        result = response.json()
                    else:
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
