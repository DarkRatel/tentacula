import logging

from fastapi import HTTPException, status, Request, Depends
from app.systems.log_event import Event
from app.systems.logging import user_id_ctx_var, event_id_ctx_var
from .user_form import User

logger = logging.getLogger("auth_get_cert")


def permission_user(permission: list[str]):
    """Функция проверки прав клиента. Если ID-клиента из сертификата есть в permission, то доступ предоставляется"""

    # Получение данных пользователя для сравнения с permission
    async def checker(user=Depends(get_current_user)) -> str | None:
        token_e_id = event_id_ctx_var.set(Event.AUTH_ERROR)
        user_id_ctx_var.set(user.username)

        try:

            if user.username not in permission:
                token_e_id = event_id_ctx_var.set(Event.AUTH_ACCESS_DENIED)
                logger.warning({'msg': 'Access denied', 'serial': user.extra['serial']})

                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

            token_e_id = event_id_ctx_var.set(Event.AUTH_SUCCESS)
            logger.info({'msg': 'Valid auth', 'serial': user.extra['serial']})

            return user.username
        finally:
            event_id_ctx_var.reset(token_e_id)

    return checker


def get_current_user(request: Request) -> User:
    """
    Механизм авторизации пользователя. Читает headers на наличие полей сертификата клиента
    """

    subject = request.headers.get('x-client-subject')
    serial = request.headers.get('x-client-serial')

    # Если не были полученные subject и serial сертификата, обработка запроса прерывается
    if not all([subject, serial]):
        token_e_id = event_id_ctx_var.set(Event.AUTH_FAILED_CREDENTIAL)
        logger.info({'msg': 'Error client certificate', 'subject': subject, 'serial': serial})
        event_id_ctx_var.reset(token_e_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Error client certificate")

    return User(username=subject, extra={'serial': serial})
