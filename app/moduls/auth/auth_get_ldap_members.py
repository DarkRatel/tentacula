import logging

import ldap
from pydantic import BaseModel
from fastapi import HTTPException, status, Request, Depends, Form

from app.ds import DSHook
from app.systems.config import AppConfig
from app.systems.log_event import Event
from app.systems.logging import event_id_ctx_var, user_id_ctx_var
from .user_form import User

logger = logging.getLogger("auth_get_ldap_members")


class Auth(BaseModel):
    """Модель для получения аутентификационных данных клиента из запроса (логина и пароля)"""
    tent_login: str
    tent_pass: str


def permission_user(permission: list[str]):
    """Функция проверки прав клиента. Если пользователь состоит в группе из permission, доступ разрешён"""

    # Получение данных пользователя для сравнения с permission
    async def checker(user=Depends(get_current_user)):
        token_e_id = event_id_ctx_var.set(Event.AUTH_ERROR)
        user_id_ctx_var.set(user.username)

        try:
            with DSHook(login=user.username, password=user.password, base=AppConfig.SECURITY__BASE,
                        host=AppConfig.SECURITY__HOST) as ds:
                l_user = ds.get_object(
                    ldap_filter=f"(&(objectCategory=person)(objectClass=user)(userPrincipalName=%s)(|%s))"
                                % (user.username, ''.join([f'(memberOf={i})' for i in permission])),
                    properties=['userPrincipalName']
                )
        except ldap.INVALID_CREDENTIALS:
            token_e_id = event_id_ctx_var.set(Event.AUTH_FAILED_CREDENTIAL)
            logger.info({'msg': 'No correct credentials'})
            event_id_ctx_var.reset(token_e_id)

            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No correct credentials")

        if not l_user:
            token_e_id = event_id_ctx_var.set(Event.AUTH_ACCESS_DENIED)
            logger.info({'msg': 'Access denied'})
            event_id_ctx_var.reset(token_e_id)

            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

        token_e_id = event_id_ctx_var.set(Event.AUTH_SUCCESS)
        logger.info({'msg': 'Valid auth'})
        event_id_ctx_var.reset(token_e_id)

        return l_user[0]['userPrincipalName']

    return checker


def get_current_user(request: Request, data: Auth) -> User:
    """
    Механизм получения логина и пароля из формы POST, для передачи в аутентификацию
    """

    return User(username=data.tent_login, password=data.tent_pass)
