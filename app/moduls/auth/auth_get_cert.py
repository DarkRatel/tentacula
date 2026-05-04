from fastapi import HTTPException, status, Request, Depends

from app.systems.logging import logger


def permission_user(permission: list[str]):
    """Функция проверки прав клиента. Если ID-клиента из сертификата есть в permission, то доступ предоставляется"""

    # Получение данных пользователя для сравнения с permission
    async def checker(user=Depends(get_current_user)):
        if user not in permission:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        return user

    return checker


def get_current_user(request: Request) -> str:
    """
    Механизм авторизации пользователя. Читает headers на наличие полей сертификата клиента
    """

    subject = request.headers.get('x-client-subject')
    serial = request.headers.get('x-client-serial')

    logger.info(f"Client cert Subject: '{subject}', Client cert Serial: {serial}")

    # Если не были полученные subject и serial сертификата, обработка запроса прерывается
    if not all([subject, serial]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Error client certificate")

    return subject
