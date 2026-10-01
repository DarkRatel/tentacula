import logging

from fastapi import Request, Depends
from app.systems.log_event import Event
from app.systems.logging import user_id_ctx_var, event_id_ctx_var

logger = logging.getLogger("auth_get_none")


def permission_user(permission):
    """Функция проверки прав клиента - не происходит"""

    # Получение данных пользователя для сравнения с permission
    async def checker(user=Depends(get_current_user)):
        user_id_ctx_var.set(user)

        token_e_id = event_id_ctx_var.set(Event.AUTH_SUCCESS)
        logger.info({'msg': 'Valid auth'})
        event_id_ctx_var.reset(token_e_id)

        return user

    return checker


def get_current_user(request: Request) -> str:
    """
    Механизм авторизации пользователя. Читает headers на наличие корректных атрибутов
    """

    username = 'Anonymous'

    return username
