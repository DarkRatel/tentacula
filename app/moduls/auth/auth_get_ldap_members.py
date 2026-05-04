import ldap
from pydantic import BaseModel
from fastapi import HTTPException, status, Request, Depends, Form

from app.ds import DSHook
from app.systems.config import AppConfig
from app.systems.logging import logger


class Auth(BaseModel):
    """Модель для получения аутентификационных данных клиента из запроса (логина и пароля)"""
    tent_login: str
    tent_pass: str


def permission_user(permission: list[str]):
    """Функция проверки прав клиента. Если пользователь состоит в группе из permission, доступ разрешён"""

    # Получение данных пользователя для сравнения с permission
    async def checker(user=Depends(get_current_user)):
        try:
            with DSHook(login=user['tent_login'], password=user['tent_pass'],
                        base=AppConfig.SECURITY__BASE, host=AppConfig.SECURITY__HOST) as ds:
                l_user = ds.get_object(
                    ldap_filter=f"(&(objectCategory=person)(objectClass=user)(userPrincipalName=%s)(|%s))"
                                % (user['tent_login'], ''.join([f'(memberOf={i})' for i in permission])),
                    properties=['userPrincipalName']
                )
        except ldap.INVALID_CREDENTIALS:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No correct credentials")

        if not l_user:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

        logger.info(f"Client DS Login: '{l_user[0]['userPrincipalName']}'")

        return l_user[0]['userPrincipalName']

    return checker


def get_current_user(request: Request, data: Auth) -> dict:
    """
    Механизм получения логина и пароля из формы POST, для передачи в аутентификацию
    """

    return {'tent_login': data.tent_login, 'tent_pass': data.tent_pass}
