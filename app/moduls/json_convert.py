"""
Функция преобразования данных Python в совместимые с JSON-форматом данные
"""
from datetime import datetime, date
from app.ds import DSDict


def json_encoder(obj):
    """Функция конвертации значений в подходящий для JSON формата"""

    if isinstance(obj, bytes):
        return f"hex:{obj.hex()}"

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


def json_decoder(obj):
    """Функция преобразования полученного JSON в исходны формат данных. Актуально для byte перекодированных в hex"""

    if isinstance(obj, str) and obj.startswith("hex:"):
        return bytes.fromhex(obj.replace("hex:", '', 1))

    if isinstance(obj, dict):
        return {k: json_decoder(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple, set)):
        return [json_decoder(v) for v in obj]

    return obj
