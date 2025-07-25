import os

from dotenv import load_dotenv
from configparser import ConfigParser

# Загружает переменных из окружения
load_dotenv()

# Получаем абсолютный путь к текущему файлу
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(CURRENT_DIR, "..", "config.cfg")

if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")


def _value(config: ConfigParser, chapter: str, name: str, type_: type = str) -> str or int:
    if os.getenv(f"TENTACULA__{chapter.upper()}__{name}"):
        if type_ == bool:
            return True if os.getenv(f"TENTACULA__{chapter.upper()}__{name}").upper() == 'TRUE' else False
        return type_(os.getenv(f"TENTACULA__{chapter.upper()}__{name}"))
    else:
        if type_ == bool:
            return config.getboolean(chapter, name)
        return type_(config.get(chapter, name))


class _AppConfig:
    def __init__(self):
        _config = ConfigParser()
        _config.read(CONFIG_PATH)

        self.SUCKERS_ENABLED = _value(_config, 'app', 'SUCKERS_ENABLED', bool)
        self.SUCKERS_FOLDER = _value(_config, 'app', 'SUCKERS_FOLDER')
        self.SCHEDULERS_ENABLED = _value(_config, 'app', 'SCHEDULERS_ENABLED', bool)
        self.SCHEDULERS_FOLDER = _value(_config, 'app', 'SCHEDULERS_FOLDER')
        self.FOLDER_LOGS = _value(_config, 'app', 'FOLDER_LOGS')
        self.DB_ASYNC_URL = _value(_config, 'app', 'DB_ASYNC_URL')

        self.SECRET_KEY = _value(_config, 'security', 'SECRET_KEY')
        self.ALGORITHM = _value(_config, 'security', 'ALGORITHM')
        self.ACCESS_TOKEN_EXPIRE_MINUTES = _value(_config, 'security', 'ACCESS_TOKEN_EXPIRE_MINUTES', int)

        self.AUTH_METHOD = _value(_config, 'security', 'AUTH_METHOD')
        if self.AUTH_METHOD == "BASIC":
            self.BASIC_USERNAME = _value(_config, 'security', 'BASIC_USERNAME')
            self.BASIC_PASSWORD = _value(_config, 'security', 'BASIC_PASSWORD')
        elif self.AUTH_METHOD == "LDAP":
            self.LDAP_URI = _value(_config, 'security', 'LDAP_URI')
            self.LDAP_PORT = _value(_config, 'security', 'LDAP_PORT')
            self.LDAP_BASE_DN = _value(_config, 'security', 'LDAP_BASE_DN')
            self.LDAP_BIND_DN = _value(_config, 'security', 'LDAP_BIND_DN')
        else:
            raise RuntimeError("AUTH_METHOD only BASIC or LDAP")


AppConfig = _AppConfig()
