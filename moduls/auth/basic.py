from moduls.auth.auth_manager import User

from systems.config import AppConfig


def authenticate(username: str, password: str) -> User or None:
    if username.lower() == AppConfig.BASIC_USERNAME.lower() and password == AppConfig.BASIC_PASSWORD:
        return User(username=username)

    return None