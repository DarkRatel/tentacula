import time
import uuid
from io import StringIO
import logging
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, SmallInteger, select, and_

from app.config import AppConfig
from app.systems.logging import logger
from app.systems.database import get_db, Base

from app.main import scheduler

name_job = "job_domain"


# Модель сессий пользователей
class Tasker(Base):
    __tablename__ = "tasker"

    id = Column(Integer, primary_key=True, index=True)
    complete = Column(Boolean, default=False, nullable=False)
    error = Column(Boolean, default=False, nullable=False)

    query = Column(String, nullable=False)
    result = Column(String, nullable=True)

    # Дата создания (всегда в UTC)
    created_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc), nullable=False)
    # Дата последнего обновления (всегда в UTC)
    updated_at = Column(DateTime(timezone=True), default=datetime.now(timezone.utc),
                        onupdate=datetime.now(timezone.utc), nullable=False)


async def run():
    # Локальный StringIO для сбора логов
    log_capture = StringIO()
    local_handler = logging.StreamHandler(log_capture)
    local_handler.setFormatter(
        logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))  # Без времени/уровня
    logger.addHandler(local_handler)

    run_id = uuid.uuid4()

    try:
        logger.info(f"RUN: {name_job}")
        logger.info(f"UID RUN: {run_id}")

        logger.info("=====")

        async for db in get_db():
            data = {'query': "Test Task"}
            user = Tasker(**data)
            db.add(user)
            await db.commit()

        time.sleep(10)
        logger.info("Pause 10 seconde")

        async for db in get_db():
            result = await db.execute(select(Tasker).where(
                (Tasker.complete == False) & (Tasker.error != True)
            ))
            task = result.scalars().first()

            if task:
                logger.info(f"Task: {task}")

                task.complete = True
                task.result = 'Result return'
                await db.commit()
            else:
                logger.info("NOT FOUND")

        logger.info("=====")

        logger.info(f"DONE")

    except RuntimeError as e:
        logger.error(f"ERROR: {e}")
    finally:
        # Получение логово из буфера
        local_handler.flush()
        log_capture.seek(0)
        log_output = log_capture.read().strip().split('\n')

        file_name = (f"{AppConfig.FOLDER_LOGS}/"
                     f"{datetime.now(timezone.utc).strftime("%Y.%m.%dT%H.%M.%S")}__{name_job}__{run_id}.log")

        logger.info(f"FILE LOGS: {file_name}")

        # Убираем временный handler, чтобы он не дублировал логи в будущем
        logger.removeHandler(local_handler)
        log_capture.close()

        with open(file_name, "w") as file:
            for item in log_output:
                file.write(f"{item}\n")


scheduler.add_job(run, "interval", minutes=1, id=name_job)
