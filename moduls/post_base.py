import uuid
from typing import Callable, Union
from io import StringIO
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, status, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from moduls.auth.auth_manager import current_user, User
from moduls.response_form import ResponseFrom
from systems.logging import logger
from systems.config import AppConfig


def create_post(path_name: str, base_model: type(BaseModel),
                func: Callable[..., Union[int, str, float, dict, bool]], router: APIRouter):
    """Функция генерации присосок"""

    p_name = '/' if path_name == '/' else f"/{path_name}"
    f_name = 'root' if path_name == '/' else path_name

    route_name = router.prefix.replace('/', '')

    def create_handler():
        async def path_function_wrapper(request: Request, data: base_model, user: User = Depends(current_user)):
            # Локальный StringIO для сбора логов
            log_capture = StringIO()
            local_handler = logging.StreamHandler(log_capture)
            local_handler.setFormatter(
                logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))  # Без времени/уровня
            logger.addHandler(local_handler)

            result = False
            run_id = uuid.uuid4()

            try:
                logger.info(f"RUN: {router.prefix}{p_name}")
                logger.info(f"UID RUN: {run_id}")
                logger.info(f"URL: {request.url}")

                logger.info(f"Protocol: {request.headers["x-forwarded-proto"].upper()}, "
                            f"Host name: {request.headers["host"]}, "
                            f"Host ip: {request.headers["x-server-ip"]}")

                logger.info(f"Client ip: {request.headers.get("x-forwarded-for")}")

                subject = request.headers.get("x-client-subject")
                serial = request.headers.get("x-client-serial")

                if any([subject, serial]):
                    logger.info(f"Client cert Subject: {subject}, Client cert Serial: {serial}")

                logger.info("=====Input data=====")
                [logger.info({r: v}) for r, v in data.model_dump().items()]
                logger.info("======Function======")
                result = func(**data.model_dump())
                logger.info("====================")

                logger.info(f"DONE")

                status_ = 'ok'
            except RuntimeError as e:
                logger.error(f"ERROR: {e}")
                status_ = 'failed'
            finally:
                # Получение логово из буфера
                local_handler.flush()
                log_capture.seek(0)
                log_output = log_capture.read().strip().split('\n')

                file_name = (f"{AppConfig.FOLDER_LOGS}/"
                             f"{datetime.now(timezone.utc).strftime("%Y.%m.%dT%H.%M.%S")}__{route_name}__"
                             f"{f_name}__{run_id}.log")

                logger.info(f"FILE LOGS: {file_name}")

                # Убираем временный handler, чтобы он не дублировал логи в будущем
                logger.removeHandler(local_handler)
                log_capture.close()

                with open(file_name, "w") as file:
                    for item in log_output:
                        file.write(f"{item}\n")

            return JSONResponse(
                ResponseFrom(username=str(user), status=status_, answer=result).model_dump(),
                status_code=status.HTTP_200_OK
            )

        # Изменение имя функции метода по формуле
        path_function_wrapper.__name__ = f"{route_name}_{f_name}_post"
        return path_function_wrapper

    handler = create_handler()
    router.add_api_route(p_name, handler, methods=["POST"])
