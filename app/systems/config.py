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
        default: Значение, которое будет выставлено по умолчанию
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
        Функция чтения значения из файла, если передана строка файла, вначале которой указано "cat ".
        Если будет передано иное, оно будет восприниматься как содержимое значение и возвращено в исходном виде
    Args:
        value: Строка со значением или путь к файлу
    Returns:
        Строка со значением
    """
    if 'cat ' in value:
        with open(value.replace('cat ', ''), 'r') as file:
            value = file.read()
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
        return json.loads(env)
    elif config.get(chapter, name):
        return json.loads(config.get(chapter, name))
    elif default is not None:
        return json.loads(default)
    else:
        raise ValueError(f"Not find [{chapter}][{name}]")


class _AppConfig:
    def __init__(self):
        """Функция со всеми переменными конфигурации полученными из env, .cfg или """
        _config = ConfigParser()
        _config.read(CONFIG_PATH, encoding='utf-8-sig')

        # [app]
        self.APP__LOGS_MASK_KEYS = _read_any(config=_config, chapter='app', name='LOGS_MASK_KEYS')
        if self.APP__LOGS_MASK_KEYS:
            self.APP__LOGS_MASK_KEYS = [i.lower() for i in self.APP__LOGS_MASK_KEYS.split(',')]
            self.APP__LOGS_MASK_KEYS = list(set(self.APP__LOGS_MASK_KEYS + ['password', 'account_password']))

        self.APP__LOGS_FOLDER = _read_any(config=_config, chapter='app', name='LOGS_FOLDER').rstrip("/")
        os.makedirs(self.APP__LOGS_FOLDER, exist_ok=True)

        self.APP__DB_ASYNC_URL = _read_any(config=_config, chapter='app', name='DB_ASYNC_URL', default=False)
        if self.APP__DB_ASYNC_URL:
            self.APP__DB_ASYNC_URL = _read_file(self.APP__DB_ASYNC_URL)

        self.APP__SECRET_KEY = _read_any(config=_config, chapter='app', name='SECRET_KEY', default=False)
        if self.APP__SECRET_KEY:
            self.APP__SECRET_KEY = _read_file(self.APP__SECRET_KEY)
            self.APP__SECRET_KEY = base64.b64decode(self.APP__SECRET_KEY.encode('utf-8'))
            self.APP__SECRET_KEY = serialization.load_pem_private_key(self.APP__SECRET_KEY, password=None)

        # [security]
        self.SECURITY__AUTHENTICATION_TYPE = _read_any(config=_config, chapter='security', name='AUTHENTICATION_TYPE')
        if self.SECURITY__AUTHENTICATION_TYPE not in ["CERTIFICATE", "NONE", "LDAP_MEMBERS"]:
            raise ValueError('AUTHENTICATION_TYPE must be CERTIFICATE, LDAP_MEMBERS or NONE')

        self.SECURITY__LIST_OF_PERMITTED = _read_json(config=_config, chapter='security', name='LIST_OF_PERMITTED',
                                                      default='[]')

        if self.SECURITY__AUTHENTICATION_TYPE == "LDAP_MEMBERS":
            self.SECURITY__HOST = _read_any(config=_config, chapter='security', name='HOST')
            self.SECURITY__BASE = _read_any(config=_config, chapter='security', name='BASE')

        # [web]
        self.WEB__NGINX_FILE = _read_any(config=_config, chapter='web', name='NGINX_FILE', default=False)
        if self.WEB__NGINX_FILE:
            os.makedirs(os.path.dirname(self.WEB__NGINX_FILE), exist_ok=True)

            self.WEB__LOGS_FOLDER = _read_any(config=_config, chapter='web', name='LOGS_FOLDER').rstrip("/")
            os.makedirs(self.WEB__LOGS_FOLDER, exist_ok=True)

            self.WEB__PORT = _read_any(config=_config, chapter='web', name='PORT', type_=int)

            self.WEB__SSL_ENABLED = _read_bool(config=_config, chapter='web', name='SSL_ENABLED', default=False)
            if self.WEB__SSL_ENABLED:
                self.WEB__SSL_CERTFILE = _read_any(config=_config, chapter='web', name='SSL_CERTFILE')
                self.WEB__SSL_KEYFILE = _read_any(config=_config, chapter='web', name='SSL_KEYFILE')
                self.WEB__SSL_CA_CERTS = _read_any(config=_config, chapter='web', name='SSL_CA_CERTS')

        # [composition]
        self.COMPOSITION__ENABLED = _read_bool(config=_config, chapter='composition', name='ENABLED', default=False)
        if self.COMPOSITION__ENABLED:
            self.COMPOSITION__TRANSIT = _read_any(config=_config, chapter='composition', name='TRANSIT')
            self.COMPOSITION__TRANSIT = _read_file('cat ' + self.COMPOSITION__TRANSIT)
            self.COMPOSITION__TRANSIT = json.loads(self.COMPOSITION__TRANSIT)

        self.COMPOSITION__LIST_OF_PERMITTED = _read_json(config=_config, chapter='composition',
                                                         name='LIST_OF_PERMITTED', default='[]')

        # [suckers]
        self.SUCKERS__ENABLED = _read_bool(config=_config, chapter='suckers', name='ENABLED', default=False)
        if self.SUCKERS__ENABLED:
            self.SUCKERS__FOLDER = _read_any(config=_config, chapter='suckers', name='FOLDER').rstrip("/")
            os.makedirs(self.SUCKERS__FOLDER, exist_ok=True)

        # [suckers_ds]
        self.SUCKERS_DS__ENABLED = _read_bool(config=_config, chapter='suckers_ds', name='ENABLED', default=False)
        self.SUCKERS_DS__LIST_OF_PERMITTED = _read_json(config=_config, chapter='suckers_ds', name='LIST_OF_PERMITTED',
                                                        default='[]')

        # [schedulers]
        self.SCHEDULERS__ENABLED = _read_bool(config=_config, chapter='schedulers', name='ENABLED', default=False)
        if self.SCHEDULERS__ENABLED:
            self.SCHEDULERS__FOLDER = _read_any(config=_config, chapter='schedulers', name='FOLDER').rstrip("/")
            os.makedirs(self.SCHEDULERS__FOLDER, exist_ok=True)

        # [schedulers_ds]
        self.SCHEDULERS_DS__ENABLED = _read_bool(config=_config, chapter='schedulers_ds', name='ENABLED', default=False)
        if self.SCHEDULERS_DS__ENABLED:
            self.SCHEDULERS_DS__TRANSIT = _read_any(config=_config, chapter='schedulers_ds', name='TRANSIT')
            self.SCHEDULERS_DS__TRANSIT = _read_file('cat ' + self.SCHEDULERS_DS__TRANSIT)
            self.SCHEDULERS_DS__TRANSIT = json.loads(self.SCHEDULERS_DS__TRANSIT)

            if not all([self.APP__DB_ASYNC_URL, self.APP__SECRET_KEY]):
                raise AttributeError("Schedulers_ds requires APP__DB_ASYNC_URL and APP__SECRET_KEY")


AppConfig = _AppConfig()
