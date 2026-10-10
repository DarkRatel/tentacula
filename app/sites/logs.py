import re
import os
import json
import logging
import typing
from pathlib import Path
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter
from pydantic import BaseModel

from app.moduls.post_base import create_post
from app.systems.config import AppConfig

logger = logging.getLogger("logs")

router_logs = APIRouter()

# Допустимые типы запросов логов
TYPE_ACCESS = typing.Literal['web_access', 'web_error', 'api']

PARS_WEB_LOG_ERROR_STR = re.compile(
    r'^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>\w+)] '
    r'(?P<pid>\d+)#(?P<tid>\d+): '
    r'(?:\*(?P<connection>\d+) )?'
    r'(?P<message>[^,]+)'
    r'(?P<dict>.*)'
)

PARS_WEB_LOG_ERROR_DICT = re.compile(r'([a-zA-Z0-9_-]+): (?:"([^"]*)"|([^,]*))')


def pars_web_error(string: str):
    """Парсин строки веб-сервера NGINX из блока error_log"""
    temp = PARS_WEB_LOG_ERROR_STR.match(string).groupdict()
    temp['time'] = datetime.strptime(temp['time'], '%Y/%m/%d %H:%M:%S').replace(tzinfo=timezone.utc).isoformat()
    temp.update({'raw': string})
    temp.update(
        {key: quoted if quoted != "" else unquoted
         for key, quoted, unquoted in PARS_WEB_LOG_ERROR_DICT.findall(temp.pop('dict'))}
    )
    return temp


def json_pars(item: str):
    """Парсинг строки логов, которая изначально сохранена в формате JSON"""
    return json.loads(item)


# Формирование списка источников логов и их привязка к ID
ID_FOLDER = {
    'web_access': (
        AppConfig.WEB__LOGS_FOLDER,
        "access*.log",
        json_pars
    ),
    'web_error': (
        AppConfig.WEB__LOGS_FOLDER,
        "error*.log",
        json_pars if AppConfig.WEB__ERROR_SUPPORT_JSON else pars_web_error
    ),
    'api': (
        AppConfig.APP__LOGS_FOLDER,
        "api*.log",
        json_pars
    )
}


def search_logs(source: str, search_depth: bool, time_start: str = None, time_end: str = None, s_id: str = None):
    """Функция опроса папки"""
    directory = Path(ID_FOLDER[source][0])

    data = []
    for file_path in directory.rglob(ID_FOLDER[source][1]) if search_depth else directory.glob(ID_FOLDER[source][1]):
        if not file_path.is_file():
            logger.info(f"Skipping {file_path} - not a files")

        with file_path.open(mode="r", encoding="utf-8", errors="replace") as log_file:

            base_name = os.path.basename(log_file.name)

            for line_number, line in enumerate(log_file, start=1):

                line = line.strip()

                if not line:
                    continue

                try:
                    line = convert_dict(ID_FOLDER[source][2](line), source=source, filename=base_name)
                except json.JSONDecodeError:
                    logger.warning({'msg': 'Error read', 'data': line})

                if time_start and not (line["time"] >= time_start):
                    continue

                if time_end and not (line["time"] < time_end):
                    continue

                if s_id and not (line["s_id"] == s_id):
                    continue

                data.append(line)

    return data


def convert_dict(dict_line: dict, source: str, filename: str):
    """
    Формирование стандартизированного словаря логов, который будет отправлен клиенту

    Args:
        dict_line: исходная строка лога
        source: Источник логов (web или api)
        filename: Имя файла-источника логов
    """
    return {
        'time': dict_line.pop("time").replace('Z', '+00:00'),
        's_id': dict_line.pop('s_id') if dict_line.get('s_id') else '-',
        'e_id': dict_line.pop('e_id') if dict_line.get('e_id') else '-',
        'u_id': dict_line.pop('u_id') if dict_line.get('u_id') else '-',
        'level': dict_line.pop("level"),
        'name': dict_line.pop('name') if dict_line.get('name') else re.sub(r"\d+", "", filename),
        'source': source,
        'filename': filename,
        'message': dict_line.pop('message') if dict_line.get('message') else "",
        'extra': dict_line['extra'] if len(dict_line) == 1 and "extra" in dict_line else dict_line,
    }


def logs(source: TYPE_ACCESS | list[TYPE_ACCESS], search_depth: bool = False, s_id: str = None,
         time_start: str = None, time_end: str = None):
    """Основная функция API получения логов"""
    for_return = []

    for source in [source] if isinstance(source, str) else source:
        for_return += search_logs(
            source,
            search_depth=search_depth,
            time_start=time_start,
            time_end=time_end,
            s_id=s_id
        )

    return for_return


class SpecData(BaseModel):
    search_depth: bool = False # Включение поиска во вложенных папках
    source: TYPE_ACCESS | list[TYPE_ACCESS] # Источник логов
    time_start: str = None # Фильтр по начальной дате поиска (больше или равно)
    time_end: str = None # Фильтр по конечной дате поиска (меньше)
    s_id: str = None # Фильтр по ID-сессии


create_post(endpoint="logs", func=logs, access=AppConfig.SECURITY__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_logs)
