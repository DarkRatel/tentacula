import json
from typing import Callable, Union, Type
from datetime import datetime, date

from pydantic import BaseModel
from fastapi import APIRouter, status, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.moduls.auth.auth_manager import current_user, User
from app.systems.logging import logger
from app.ds import DSDict

STEP = 1500  # Общая переменная шага для списков, которые будут возвращены


async def json_stream(lst: list | tuple | set):
    try:
        yield "["  # начало массива

        for l in range(0, len(lst), STEP):
            end = l + STEP
            split = ',' if end <= len(lst) else ''
            yield ','.join([json.dumps(json_encoder(i)) for i in lst[l:end]]) + split

        yield "]"  # конец массива

    except Exception as e:
        logger.warning(f"Stream interrupted: {e}")
    finally:
        lst = None


def json_encoder(obj):
    """Функция конвертации значений в подходящий для JSON формат"""
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


def create_post(endpoint: str, base_model: Type[BaseModel],
                func: Callable[..., Union[int, str, float, list, tuple, dict, bool, None]], router: APIRouter):
    """
    Функция генерации присосок.
    Если присоска предполагает возращение списка, он будет возращён частями, если элементов больше 1500 (по умолчанию).

    Args:
        endpoint: Имя эндпоинта. Может быть либо /, либо без указания глубины (дополнительного использования /)
        base_model: BaseModel входных данных
        func: Функция для исполнения
        router: APIRouter
    """

    if '/' == endpoint:
        name_func = 'root'
    elif '/' in endpoint:
        raise ValueError(f"Недопустимое имя эндпоинта: {endpoint}")
    else:
        name_func = endpoint

    endpoint = '/' if endpoint == '/' else f"/{endpoint}"

    route_name = router.prefix.replace('/', '')

    def create_handler():
        """Функция создания функции для эндпоинта"""

        async def path_function_wrapper(request: Request, data: base_model, user: User = Depends(current_user)):
            try:
                input_dada = data.model_dump()

                # Вывод входных данных в логи
                logger.info("Input data: %s", input_dada)
                logger.info("======Function======")
                # Исполнение функции
                result = func(**input_dada)
                logger.info("====================")

                if isinstance(result, list) and len(result) > STEP:
                    return StreamingResponse(json_stream(result), media_type="text/event-stream")

                return JSONResponse(content=json_encoder(result), status_code=status.HTTP_200_OK)

            except Exception as result:
                logger.error(f"ERROR: {result}")
                return JSONResponse(content=str(result), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            finally:
                # Обнуление результатов
                result = None
                logger.error(f"DONE")

        # Изменение имя функции метода по формуле, для избегания повторений в именах функций
        path_function_wrapper.__name__ = f"{route_name}_{name_func}_post"
        return path_function_wrapper

    handler = create_handler()
    router.add_api_route(endpoint, handler, methods=["POST"])
