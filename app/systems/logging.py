import ast
import json
import re
import copy
import logging
from datetime import datetime, timezone

import contextvars
import sys

from app.systems.config import AppConfig

# Преобразование списка ключей маскирования, в регулярное выражение
MASK_COMPILE = re.compile(f"{'|'.join([f'^{i}$' for i in AppConfig.APP__LOGS_MASK_KEYS])}", flags=re.IGNORECASE)


def mask_dict(data):
    """Функция маскирования значений, если выводится словарь и ключ содержит одно из ключевых значений"""
    if isinstance(data, dict):
        return {k: ("***" if MASK_COMPILE.search(k) else mask_dict(v)) for k, v in data.items()}
    elif isinstance(data, (list, tuple)):
        return type(data)(mask_dict(v) for v in data)
    return data


# Контекстная переменная для текущего кода сессии.
# Используется в middleware, для получения из контекста ID-сессии
session_id_ctx_var: contextvars.ContextVar[str] = contextvars.ContextVar("s_id", default="-")
event_id_ctx_var: contextvars.ContextVar[str] = contextvars.ContextVar("e_id", default="system")
user_id_ctx_var: contextvars.ContextVar[str] = contextvars.ContextVar("u_id", default="tent")

# Класс для логов в формате JSON
class SafeJsonFormatter(logging.Formatter):
    def format(self, record):

        record.s_id = session_id_ctx_var.get()
        record.e_id = record.e_id if hasattr(record, "e_id") else event_id_ctx_var.get()
        record.u_id = record.u_id if hasattr(record, "u_id") else user_id_ctx_var.get()

        if not hasattr(record, "_extra"):
            record._extra = {}

        # Блок маскирования значений в логах
        if record.args:
            record.args = mask_dict(copy.deepcopy(record.args))

            msg = record.getMessage()
            record.args = ()
        else:
            msg = record.getMessage()
            try:
                temp = ast.literal_eval(msg)
                record._extra = mask_dict(temp)
                msg = record._extra.pop('msg') if 'msg' in temp else ""
            except Exception:
                pass

        record.msg = msg

        return json.dumps({
            "time": self.formatTime(record, self.datefmt),
            "s_id": record.s_id,
            "e_id": record.e_id,
            "u_id": record.u_id,
            "level": record.levelname,
            "name": record.name,
            "message": record.msg,
            "extra": record._extra
        })

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds")

# Класс для логов в стандартном формате
class SafeFormatter(logging.Formatter):
    def format(self, record):
        record.s_id = session_id_ctx_var.get()
        record.e_id = event_id_ctx_var.get()
        record.u_id = user_id_ctx_var.get()

        if not hasattr(record, "_extra"):
            record._extra = {}

        # Блок маскирования значений в логах
        if record.args:
            record.args = mask_dict(copy.deepcopy(record.args))

            msg = record.getMessage()
            record.args = ()
        else:
            msg = record.getMessage()
            try:
                temp = ast.literal_eval(msg)
                record._extra = mask_dict(temp)
                msg = record._extra.pop('msg') if 'msg' in temp else ""
            except Exception:
                pass

        record.msg = msg

        return super().format(record)

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds")

# Заполнение переменных формата логов и класса обработки логов
if AppConfig.APP__LOGS_JSON:
    LOG_FORMAT = ('{'
                  '"time":"%(asctime)s",'
                  '"s_id":"%(s_id)s",'
                  '"e_id":"%(e_id)s",'
                  '"u_id":"%(u_id)s",'
                  '"level":"%(levelname)s",'
                  '"name":"%(name)s",'
                  '"msg":"%(message)s",'
                  '"extra":%(_extra)s'
                  '}')
    Formatter = SafeJsonFormatter
else:
    LOG_FORMAT = "[%(asctime)s] [%(s_id)s|%(levelname)s|%(name)s] %(message)s %(_extra)s"
    Formatter = SafeFormatter

file_handler = logging.FileHandler(f"{AppConfig.APP__LOGS_FOLDER}/api.log", encoding="utf-8")
file_handler.setFormatter(Formatter(LOG_FORMAT))

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(Formatter(LOG_FORMAT))


def setup_logging():
    """Функция подключения логирования в приложении"""
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    root.handlers.clear()
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    for name in ["uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"]:
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
        logger.setLevel(logging.INFO)
