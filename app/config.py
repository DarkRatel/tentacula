import os
import json

from dotenv import load_dotenv
from configparser import ConfigParser

# Загрузка переменных из окружения
load_dotenv()

# Получаем абсолютный путь к текущему файлу
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.normpath(os.path.join(CURRENT_DIR, "..", "config.cfg"))

if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")


def _value(config: ConfigParser, chapter: str, name: str, type_: type = str) -> str | int:
    if os.getenv(f"TENTACULA__{chapter.upper()}__{name}"):
        if type_ == bool:
            return True if os.getenv(f"TENTACULA__{chapter.upper()}__{name}").upper() == 'TRUE' else False
        return type_(os.getenv(f"TENTACULA__{chapter.upper()}__{name}"))
    else:
        if type_ == bool:
            return config.getboolean(chapter, name)
        return type_(config.get(chapter, name))


def _read_json(config: ConfigParser, chapter: str, name: str):
    path = os.getenv(f"TENTACULA__{chapter.upper()}__{name}") or config.get(chapter, name)
    with open(path) as f:
        return json.loads(f.read())


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

        self.PORT = _value(_config, 'web', 'PORT', int)
        self.RELOAD = _value(_config, 'web', 'RELOAD', bool)
        self.USE_SSL = _value(_config, 'web', 'USE_SSL')

        if self.USE_SSL:
            self.SSL_CERTFILE = _value(_config, 'web', 'SSL_CERTFILE')
            self.SSL_KEYFILE = _value(_config, 'web', 'SSL_KEYFILE')
            self.SSL_CA_CERTS = _value(_config, 'web', 'SSL_CA_CERTS')
            self.SSL_CERT_REQS = _value(_config, 'web', 'SSL_CERT_REQS', int)

        self.TRANSIT = _read_json(_config, 'composition', 'TRANSIT')


AppConfig = _AppConfig()
