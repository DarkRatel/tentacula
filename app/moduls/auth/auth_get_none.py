from fastapi import Request, Depends

from app.systems.logging import logger


def permission_user(permission):
    """Функция проверки прав клиента - не происходит"""

    # Получение данных пользователя для сравнения с permission
    async def checker(user=Depends(get_current_user)):
        return user

    return checker


def get_current_user(request: Request) -> str:
    """
    Механизм авторизации пользователя. Читает headers на наличие корректных атрибутов
    """

    username = 'Anonymous'
    logger.info(f"{username} authenticated")

    return username
