from fastapi import HTTPException, status, Request
from pydantic import BaseModel

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

    subject = request.headers.get('x-client-subject')
    serial = request.headers.get('x-client-serial')

    logger.info(f"Client ip: {request.headers.get('x-forwarded-for')}, "
                f"Client cert Subject: {subject}, Client cert Serial: {serial}")

    # Если не были полученные subject и serial сертификата, обработка запроса прерывается
    if not all([subject, serial]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Error client certificate")

    return User(username=subject)
