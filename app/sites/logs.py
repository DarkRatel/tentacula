import re
import os
import json
import logging
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

from app.moduls.post_base import create_post
from app.systems.config import AppConfig

logger = logging.getLogger("logs")

router_logs = APIRouter()

# Формирование списка источников логов и их привязка к ID
ID_FOLDER = {
    'web': AppConfig.WEB__LOGS_FOLDER,
    'api': AppConfig.APP__LOGS_FOLDER
}


class SpecData(BaseModel):
    source: str = 'web,api'
    time_start: str = None
    time_end: str = None
    s_id: str = None


def search_logs(source: str, time_start: str = None, time_end: str = None, s_id: str = None):
    directory = Path(ID_FOLDER[source])

    data = []
    for file_path in directory.rglob("*.log"):
        if not file_path.is_file():
            logger.info(f"Skipping {file_path} - not a files")

        with file_path.open(mode="r", encoding="utf-8", errors="replace") as log_file:

            base_name = os.path.basename(log_file.name)

            for line_number, line in enumerate(log_file, start=1):

                line = line.strip()

                if not line:
                    continue

                try:
                    line = convert_dict(json.loads(line), source=source, filename=base_name)
                except json.JSONDecodeError:
                    logger.warning({'msg': 'Error read', 'data': data})

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


def logs(source: str = 'web,api', time_start: str = None, time_end: str = None, s_id: str = None):
    for_return = []

    for source in source.split(','):
        for_return += search_logs(source, time_start=time_start, time_end=time_end, s_id=s_id)

    return for_return


create_post(endpoint="logs", func=logs, access=AppConfig.SECURITY__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_logs)
