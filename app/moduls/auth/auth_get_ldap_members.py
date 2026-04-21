import ldap

from fastapi import HTTPException, status, Request, Depends, Form

from app.ds import DSHook
from app.systems.config import AppConfig
from app.systems.logging import logger


def permission_user(permission: list[str]):
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


def get_current_user(request: Request, tent_login: str = Form(...), tent_pass: str = Form(...)) -> dict:
    """
    Механизм получения логина и пароля из формы POST, для передачи в аутентификацию
    """

    return {'tent_login': tent_login, 'tent_pass': tent_pass}
