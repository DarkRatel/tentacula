"""
Функция создания эндпоинтов в виде готовых Присосок, с учётом всей специфики работы Тентакли
"""
import json
from typing import Callable, Union, Type, Awaitable

import asyncio
from pydantic import BaseModel
from fastapi import APIRouter, status, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.moduls.auth import get_current_user
from app.systems.logging import logger
from app.moduls.json_encoder import json_encoder

STEP = 1500  # Общая переменная шага для списков, которые будут возвращены
BEFORE_ANSWERING = 15  # Пауза в секундах, перед тем, как эндпоинт передаст пустой байт для активности в сессии
# Допустимые типы данных, которые могут быть возвращены эндпоинтом
ReturnType = Union[int, str, float, list, tuple, dict, bool, None]


async def stream_result(func, param):
    """
    Функция стриминга ответа клиенту.
    Стримится один большой JSON, в рамках которого и получен ли успешный ответ в рамках запроса
    """
    logger.info("======Function======")
    yield "{"
    # Отправляется для отправки 0 байт, пока на эндпоинте идёт обработка
    yield '"waiting": "'

    result = None
    try:
        task = asyncio.create_task(func(**param))

        pause_active = BEFORE_ANSWERING
        while not task.done():
            await asyncio.sleep(1)
            pause_active -= 1

            if pause_active <= 0:
                pause_active = BEFORE_ANSWERING
                yield ''

        result = task.result()
        error = False
    except Exception as e:
        logger.warning(f"Stream interrupted: {e}")
        result = e
        error = True

    # Конец блока waiting и передача данных была ли зафиксирована ошибка
    yield f'", error": {str(error).lower()}, '

    # Открытие блока для результата исполнения запроса на эндпоинте
    yield '"details": '

    # Если будет список с элементами больше чем STEP, то он будет отправляться по частям
    if isinstance(result, list):
        yield "["  # начало массива

        for l in range(0, len(result), STEP):
            end = l + STEP
            split = ',' if end <= len(result) else ''
            yield ','.join([json.dumps(json_encoder(i)) for i in result[l:end]]) + split

        yield "]"  # конец массива

    elif result is None:
        yield "null"
    elif isinstance(result, dict):
        yield json.dumps(json_encoder(result))
    else:
        yield str(json.dumps(str(result), ensure_ascii=False))

    yield "}"
    logger.info("======End======")


def create_post(router: APIRouter,
                endpoint: str, base_model: Type[BaseModel], func: Callable[..., Awaitable[ReturnType]],
                access: list[str] = None) -> None:
    """
    Функция генерации присосок.
    Если присоска предполагает возращение списка, он будет возращён частями, если элементов больше 1500 (по умолчанию).

    Args:
        endpoint: Имя эндпоинта. Может быть либо /, либо без указания глубины (дополнительного использования /)
        base_model: BaseModel входных данных
        func: Функция для исполнения
        router: APIRouter
        access: Список ID-клиентов, которые могут быть воспользоваться эндпоинтом (используется если включена аутентификация)
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

        async def path_function_wrapper(request: Request, data: base_model, user=Depends(get_current_user(access))):
            """Функция исполняющаяся внутри эндпоинта"""
            try:
                # Преобразование полученных значений
                input_dada = data.model_dump()

                # Вывод входных данных в логи
                logger.info("Input data: %s", input_dada)

                return StreamingResponse(stream_result(func, input_dada), media_type="text/event-stream")

            except Exception as result:
                logger.error(f"ERROR: {result}")
                return JSONResponse(content=str(result), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Изменение имя функции метода по формуле, для избегания повторений в именах функций
        path_function_wrapper.__name__ = f"{route_name}_{name_func}_post"
        return path_function_wrapper

    handler = create_handler()
    router.add_api_route(endpoint, handler, methods=["POST"])
