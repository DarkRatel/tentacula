import json
import re
import copy
import logging
from datetime import datetime, timezone

import contextvars
from logging.handlers import RotatingFileHandler
import sys

from app.systems.config import AppConfig

# Преобразование списка ключей маскирования, в регулярное выражение
MASK_COMPILE = re.compile(f"{'|'.join([f'^{i}$' for i in AppConfig.LOGS_MASK_KEYS])}", flags=re.IGNORECASE)


def mask_dict(data):
    """Функция маскирования значений, если выводится словарь и ключ содержит одно из ключевых значений"""
    if isinstance(data, dict):
        return {k: ("***" if MASK_COMPILE.search(k) else mask_dict(v)) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return type(data)(mask_dict(v) for v in data)
    return data


# Контекстная переменная для текущего кода сессии.
# Используется в middleware, для получения из контекста ID-сессии
s_id_ctx_var = contextvars.ContextVar("s_id", default="-")


class SafeFormatter(logging.Formatter):
    def format(self, record):
        # Если кода сессии нет, применяется значение по умолчанию
        record.s_id = s_id_ctx_var.get("-")

        # Блок маскирования значений в логах
        if record.args:
            safe_args = mask_dict(copy.deepcopy(record.args))
            record.args = safe_args
        else:
            msg = record.getMessage()
            try:
                msg = json.loads(msg)
                msg = mask_dict(msg)
            except Exception:
                try:
                    msg = mask_dict(eval(msg))
                except Exception:
                    pass
            record.msg = msg

        return super().format(record)

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds")


LOG_FORMAT = "[%(asctime)s] [%(s_id)s|%(levelname)s|%(name)s] %(message)s"

file_handler = logging.FileHandler(
    f'{AppConfig.LOGS_FOLDER}/api.log',
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


def setup_logging():
    class GlobalLogger(logging.Logger):
        def __init__(self, name):
            super().__init__(name)

            self.handlers = [file_handler, console_handler]
            self.propagate = False
            self.setLevel(logging.INFO)

    logging.setLoggerClass(GlobalLogger)
