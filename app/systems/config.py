import base64
import os
import json

from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
from configparser import ConfigParser

# Загрузка переменных из окружения
load_dotenv()

# Получаем абсолютный путь к текущему файлу
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Ожидается, что конфигурационный файл будет на папку ниже
CONFIG_PATH = os.path.normpath(os.path.join(CURRENT_DIR, "..", "..", "config.cfg"))

# Проверка, что файл найден
if not os.path.exists(CONFIG_PATH):
    raise FileNotFoundError(f"Config file not found: {CONFIG_PATH}")


def _read_bool(config: ConfigParser, chapter: str, name: str, default: bool = None) -> bool:
    """
    Функция конвертации буллевых значений из параметров конфигурации
    Args:
        config: Прочтённый файл конфигурации
        chapter: Область конфигурационного файла
        name: Переменная
        default: Значение, которое будет выставлено по умолчанию, если
    Returns:
        Буллевое значение
    """
    env = os.getenv(f"TENTACULA__{chapter.upper()}__{name.upper()}")

    if env:
        if env.upper() == 'TRUE':
            return True
        elif env.upper() == 'FALSE':
            return False
        else:
            raise ValueError(f"Invalid value for {name}")
    elif config.getboolean(chapter, name):
        return config.getboolean(chapter, name)
    elif default is not None:
        return default
    else:
        raise ValueError(f"Not find [{chapter}][{name}]")


def _read_any(config: ConfigParser, chapter: str, name: str, type_: type = str, default=None):
    """
    Функция конвертации любых значений из параметров конфигурации
    Args:
        config: Прочтённый файл конфигурации
        chapter: Область конфигурационного файла
        name: Переменная
        type_: Ожидаемый тип атрибута
        default: Значение, которое будет выставлено по умолчанию, если
    Returns:
        Итоговое значение
    """
    env = os.getenv(f"TENTACULA__{chapter.upper()}__{name.upper()}")

    if env:
        return type_(env)
    elif config.get(chapter, name):
        return type_(config.get(chapter, name))
    elif default is not None:
        return default
    else:
        raise ValueError(f"Not find [{chapter}][{name}]")


def _read_file(value: str) -> str:
    """
        Функция чтения значения из файла, если передан строка
    Args:
        value: Строка со значением или путь к файлу
    Returns:
        Строка со значением
    """
    if value.startswith('/'):
        with open(value, 'r') as file:
            return file.read()
    return value


def _read_json(config: ConfigParser, chapter: str, name: str, default=None) -> dict:
    """
        Функция чтения файла с JSON и конвертация в словарь
    Args:
        config: Прочтённый файл конфигурации
        chapter: Область конфигурационного файла
        name: Переменная
    Returns:
        Словарь
    """
    env = os.getenv(f"TENTACULA__{chapter.upper()}__{name.upper()}")

    if env:
        return json.loads(_read_file(env))
    elif config.get(chapter, name):
        return json.loads(_read_file(config.get(chapter, name)))
    elif default is not None:
        return default
    else:
        raise ValueError(f"Not find [{chapter}][{name}]")


class _AppConfig:
    def __init__(self):
        _config = ConfigParser()
        _config.read(CONFIG_PATH, encoding='utf-8-sig')

        # Настройка сочлинения
        self.COMPOSITION_ENABLED = _read_bool(config=_config, chapter='app', name='COMPOSITION_ENABLED', default=False)

        # Настройки присосок
        self.SUCKERS_ENABLED = _read_bool(config=_config, chapter='app', name='SUCKERS_ENABLED', default=False)
        if self.SUCKERS_ENABLED:
            self.SUCKERS_FOLDER = _read_any(config=_config, chapter='app', name='SUCKERS_FOLDER').rstrip("/")
            os.makedirs(self.SUCKERS_FOLDER, exist_ok=True)

        self.SUCKERS_DS = _read_bool(config=_config, chapter='app', name='SUCKERS_DS', default=False)

        # Настройка шедуллера
        self.SCHEDULERS_ENABLED = _read_bool(config=_config, chapter='app', name='SCHEDULERS_ENABLED', default=False)
        if self.SCHEDULERS_ENABLED:
            self.SCHEDULERS_FOLDER = _read_any(config=_config, chapter='app', name='SCHEDULERS_FOLDER').rstrip("/")
            os.makedirs(self.SCHEDULERS_FOLDER, exist_ok=True)

        self.SCHEDULERS_DS = _read_bool(config=_config, chapter='app', name='SCHEDULERS_DS', default=False)

        if self.SCHEDULERS_DS:
            self.DB_ASYNC_URL = _read_any(config=_config, chapter='app', name='DB_ASYNC_URL', default=None)
            self.DB_ASYNC_URL = _read_file(self.DB_ASYNC_URL)
            if 'cat ' in self.DB_ASYNC_URL:
                with open(self.DB_ASYNC_URL.replace('cat ', ''), 'r') as file:
                    self.DB_ASYNC_URL = file.read()

            self.SECRET_KEY = _read_any(config=_config, chapter='app', name='SECRET_KEY', default=None)
            self.SECRET_KEY = _read_file(self.SECRET_KEY)
            if 'cat ' in self.SECRET_KEY:
                with open(self.SECRET_KEY.replace('cat ', ''), 'r') as file:
                    self.SECRET_KEY = file.read()
            self.SECRET_KEY = base64.b64decode(self.SECRET_KEY.encode('utf-8'))
            self.SECRET_KEY = serialization.load_pem_private_key(self.SECRET_KEY, password=None)

        # Параметры логирования приложения
        self.LOGS_FOLDER = _read_any(config=_config, chapter='app', name='LOGS_FOLDER').rstrip("/")
        os.makedirs(self.LOGS_FOLDER, exist_ok=True)

        self.LOGS_MASK_KEYS = _read_any(config=_config, chapter='app', name='LOGS_MASK_KEYS')
        if self.LOGS_MASK_KEYS:
            self.LOGS_MASK_KEYS = [i.lower() for i in self.LOGS_MASK_KEYS.split(',')]
            self.LOGS_MASK_KEYS = list(set(self.LOGS_MASK_KEYS + ['password', 'account_password']))

        # Настройка NGINX
        self.NGINX_FILE = _read_any(config=_config, chapter='web', name='NGINX_FILE', default=False)
        if self.NGINX_FILE:
            os.makedirs(os.path.dirname(self.NGINX_FILE), exist_ok=True)

            self.NGINX_FOLDER_LOGS = _read_any(config=_config, chapter='web', name='NGINX_FOLDER_LOGS').rstrip("/")
            os.makedirs(self.NGINX_FOLDER_LOGS, exist_ok=True)

            self.PORT = _read_any(config=_config, chapter='web', name='PORT', type_=int)
            self.SSL_CERTFILE = _read_any(config=_config, chapter='web', name='SSL_CERTFILE')
            self.SSL_KEYFILE = _read_any(config=_config, chapter='web', name='SSL_KEYFILE')
            self.SSL_CA_CERTS = _read_any(config=_config, chapter='web', name='SSL_CA_CERTS')

        self.TRANSIT = _read_json(config=_config, chapter='composition', name='TRANSIT', default=None)


AppConfig = _AppConfig()
