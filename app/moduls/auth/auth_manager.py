from fastapi import HTTPException, status, Request
from pydantic import BaseModel

from app.systems.config import AppConfig
from app.systems.logging import logger


class User(BaseModel):
    username: str


def current_user(request: Request) -> User | None:
    """
    Механизм авторизации пользователя. Читает headers на наличие корректных атрибутов
    """
    logger.info(f"Protocol: {request.headers['x-forwarded-proto'].upper()}, "
                f"Host name: {request.headers['host']}, "
                f"Host ip: {request.headers['x-server-ip']}, "
                f"URL: {request.url}")

    username = 'Anonymous'

    # Если включена аутентификация пользователя по сертификату
    if AppConfig.AUTHENTICATION_TYPE == 'CERTIFICATE':
        subject = request.headers.get('x-client-subject')
        serial = request.headers.get('x-client-serial')

        logger.info(f"Client ip: {request.headers.get('x-forwarded-for')}, "
                    f"Client cert Subject: '{subject}', Client cert Serial: {serial}")

        # Если не были полученные subject и serial сертификата, обработка запроса прерывается
        if not all([subject, serial]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Error client certificate")

        # Проверка наличия сертификата в разрешённых
        if subject not in AppConfig.LIST_OF_CERTIFICATES:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Certificate subject not allowed")

        username = subject

    return User(username=username)
