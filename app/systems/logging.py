import logging
from datetime import datetime, timezone

import contextvars
from logging.handlers import RotatingFileHandler
import sys

from app.systems.config import AppConfig

# Контекстная переменная для текущего кода сессии.
# Используется в middleware, для получения из контекста ID-сессии
s_id_ctx_var = contextvars.ContextVar("s_id", default="-")


class SafeFormatter(logging.Formatter):
    def format(self, record):
        # Если кода сессии нет, применяется значение по умолчанию
        record.s_id = s_id_ctx_var.get("-")
        return super().format(record)

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds")

LOG_FORMAT = "[%(asctime)s] [%(s_id)s|%(levelname)s|%(name)s] %(message)s"

file_handler = RotatingFileHandler(
    f'{AppConfig.FOLDER_LOGS}/api.log',
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8"
)
file_handler.setFormatter(SafeFormatter(LOG_FORMAT))

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(SafeFormatter(LOG_FORMAT))

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Заменяем handlers корневого логгера
logger.handlers = [file_handler, console_handler]

for name in ["uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"]:
    logger = logging.getLogger(name)
    logger.handlers = [file_handler, console_handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
