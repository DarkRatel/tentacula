from moduls.auth.auth_manager import User

from systems.config import AppConfig

def authenticate(username: str, password: str) -> User or None:
    #TODO: Добавить авторизацию по LDAP

    return None