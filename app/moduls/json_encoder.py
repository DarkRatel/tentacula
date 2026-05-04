"""
Функция преобразования данных Python в совместимые с JSON-форматом данные
"""
from datetime import datetime, date
from app.ds import DSDict

def json_encoder(obj):
    """Функция конвертации значений в подходящий для JSON формата"""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, dict):
        return {k: json_encoder(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set)):
        return [json_encoder(v) for v in obj]

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()

    if isinstance(obj, DSDict):
        return obj.original_dict()

    raise TypeError(repr(obj) + " is not JSON serializable")