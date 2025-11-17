from typing import Callable, Union, Type

from pydantic import BaseModel
from fastapi import APIRouter, status, Depends, Request
from fastapi.responses import JSONResponse

from app.moduls.auth.auth_manager import current_user, User
from app.moduls.response_form import ResponseFrom
from app.systems.logging import logger


def create_post(endpoint: str, base_model: Type[BaseModel],
                func: Callable[..., Union[int, str, float, list, tuple, dict, bool, None]], router: APIRouter):
    """
    Функция генерации присосок

    Args:
        endpoint: Имя эндпоинта. Может быть либо "/", либо без указания глубины (дополнительного использования "/")
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

    route_name = router.prefix.replace('/', '')

    def create_handler():
        async def path_function_wrapper(request: Request, data: base_model, user: User = Depends(current_user)):

            try:
                input_dada = data.model_dump()

                # Вывод входных данных в логи
                logger.info("Input data: %s", input_dada)
                logger.info("======Function======")
                # Исполнение функции
                result = func(**input_dada)
                logger.info("====================")

                logger.info(f"DONE")

                successfully = True
            except Exception as e:
                logger.error(f"ERROR: {e}")
                successfully = False
                result = str(e)

            return JSONResponse(
                ResponseFrom(username=user.username, successfully=successfully, answer=result).model_dump(mode="json"),
                status_code=status.HTTP_200_OK
            )

        # Изменение имя функции метода по формуле, для избегания повторений в именах функций
        path_function_wrapper.__name__ = f"{route_name}_{name_func}_post"
        return path_function_wrapper

    handler = create_handler()
    router.add_api_route(endpoint, handler, methods=["POST"])
