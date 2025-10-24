import json
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


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def create_post(path_name: str, base_model: BaseModel,
                func: Callable[..., Union[int, str, float, list, tuple, dict, bool, None]], router: APIRouter):
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
                logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
            logger.addHandler(local_handler)

            run_id = uuid.uuid4()

            try:
                logger.info(f"RUN: {router.prefix}{p_name}")
                logger.info(f"UID RUN: {run_id}")
                logger.info(f"URL: {request.url}")

                logger.info(f"Protocol: {request.headers['x-forwarded-proto'].upper()}, "
                            f"Host name: {request.headers['host']}, "
                            f"Host ip: {request.headers['x-server-ip']}, "
                            f"Request-ID: {request.headers['x-request-id']}")

                logger.info(f"Client ip: {request.headers.get('x-forwarded-for')}")

                subject = request.headers.get("x-client-subject")
                serial = request.headers.get("x-client-serial")

                if any([subject, serial]):
                    logger.info(f"Client cert Subject: {subject}, Client cert Serial: {serial}")

                logger.info("=====Input data=====")
                [logger.info({r: v}) for r, v in data.model_dump().items()]
                logger.info("======Function======")
                result = func(**data.model_dump())
                result = json.dumps(result, default=json_serial)
                logger.info("====================")

                logger.info(f"DONE")

                successfully = True
            except Exception as e:
                logger.error(f"ERROR: {e}")
                successfully = False
                result = str(e)
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
                ResponseFrom(username=str(user), successfully=successfully, answer=result).model_dump(),
                status_code=status.HTTP_200_OK
            )

        # Изменение имя функции метода по формуле
        path_function_wrapper.__name__ = f"{route_name}_{f_name}_post"
        return path_function_wrapper

    handler = create_handler()
    router.add_api_route(p_name, handler, methods=["POST"])
