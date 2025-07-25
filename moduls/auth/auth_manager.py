from importlib import import_module

from fastapi import Header, HTTPException, status
from pydantic import BaseModel

from systems.config import AppConfig


class User(BaseModel):
    username: str


def get_auth_module():
    """Функция выбора функции метода авторизации"""
    if AppConfig.AUTH_METHOD == 'LDAP':
        auth_module = import_module('moduls.auth.ldap')
    elif AppConfig.AUTH_METHOD == 'BASIC':
        auth_module = import_module('moduls.auth.basic')
    else:
        raise RuntimeError("Not valid AUTH_METHOD")
    return auth_module


def current_user(username: str = Header(...), password: str = Header(...)) -> User or None:
    """Функция авторизации пользователя на основе логина, пароля и секрутного ключа переданных в Header"""

    # TODO: УБрать проверку секретного ключа, если не будет нужна
    # if secret_key != AppConfig.SECRET_KEY:
    #     raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Failed secret-key")

    # Выбор функции способа авторизации
    auth_module = get_auth_module()
    # Авторизация
    user = auth_module.authenticate(username=username, password=password)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Error username or password")

    return user
