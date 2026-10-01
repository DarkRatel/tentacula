from dataclasses import dataclass


@dataclass
class User:
    """Форма для авторизации пользователя"""
    username: str
    password: str = None
    extra: dict = None
