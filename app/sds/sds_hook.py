import os
import json
import logging
import time
import base64
from datetime import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

import httpx, ssl
import psycopg2
from pydantic_core import ErrorDetails

from app.ds import DSHook, DSDict
from app.ds import DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY


def datetime_parser(dct):
    for k, v in dct.items():
        if isinstance(v, list):
            if isinstance(v, str):
                try:
                    dct[k] = datetime.fromisoformat(v)
                except ValueError:
                    pass
        if isinstance(v, str):
            try:
                dct[k] = datetime.fromisoformat(v)
            except ValueError:
                pass
    return dct


def encode_param(_public_key, param: dict):
    param = json.dumps(param).encode("utf-8")

    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, param, None)

    # Шифрование AES-ключа RSA
    encrypted_aes_key = _public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(
        len(encrypted_aes_key).to_bytes(4, "big") + encrypted_aes_key + nonce + ciphertext
    ).decode('utf-8')


def request_db(_connect, db_table: str, timeout: int, type_query, param_conn, param_query):
    with _connect:
        with _connect.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO {db_table} (status, type_query, param_conn, param_query)
                VALUES ('waiting', '{type_query}', '{param_conn}', '{param_query}')
                RETURNING id
                """
            )
            query_id = cur.fetchone()[0]
            print(query_id)

    time.sleep(10)

    with _connect:
        with _connect.cursor() as cur:
            for _ in range(int(timeout / 10)):
                cur.execute(
                    f"""
                    SELECT status, result
                    FROM {db_table}
                    WHERE id = {query_id} AND (status = 'complete' OR status = 'error')
                    """
                )

                result = cur.fetchone()

                if isinstance(result, tuple):
                    cur.execute(f"DELETE FROM {db_table} WHERE id = {query_id}")

                    if result[0] == 'error':
                        raise RuntimeError(result[1])

                    if isinstance(result[1], list):
                        return [DSDict(i) for i in result[1]]
                    return result[1]

                time.sleep(int(timeout / 10))
            else:
                raise TimeoutError("Данные не появились за 5 минут")


class SDSHook:
    CONN_DS = 1
    CONN_TENT = 2
    CONN_DB = 3

    def __init__(self, login: str = None, password: str = None, host: str = None, port: int = 636, base: str = None,
                 dry_run: bool = False, log_level: int = logging.INFO,
                 public_key: str = None, timeout: int = 300,
                 db_login: str = None, db_password: str = None, db_host: str = None, db_port: int = 5432,
                 database: str = None,
                 url: str = None, cert_root: str = None, cert_file: str = None, cert_key: str = None,
                 airflow_conn_id: str = None) -> None:
        """
        Класс создаёт сессию с DS, в рамках который будет исполнен запрос к каталогу
        (запрос описывается в рамках наследованных функций).

        Args:
            login: Логин учётной записи, от имени который создаётся сессия в DS
            password: Пароль от учётной записи
            host: Адрес контроллера домена
            port: Порт подключения: 389 или 636 (по умолчанию 636)
            base: Область каталога. Если не указать, при открытии сессии у DS будет запрошена область работы
            dry_run: Формирование запроса, без внесения изменений в DS
            log_level: Тип логирования (принимает значения от logging)
        """

        if any([airflow_conn_id]):
            from airflow.hooks.base_hook import BaseHook
            _config = BaseHook.get_connection(airflow_conn_id)

            login = _config.login
            password = _config.password
            host = _config.host
            port = _config.port
            base = _config.schema

            _data = json.loads(_config.get_extra())
            url = _data.get("url", None)
            public_key = _data.get("public_key", None)

            cert_root = _data.get("cert_root", None)
            cert_file = _data.get("cert_file", None)
            cert_key = _data.get("cert_key", None)
            dry_run = _data.get("dry_run", None)
            log_level = _data.get("log_level", None)
            timeout = _data.get("timeout", None)

            db_conn_id = _data.get("db_conn_id", None)
            if db_conn_id:
                _config = BaseHook.get_connection(db_conn_id)
                db_login = _config.login
                db_password = _config.password
                db_host = _config.host
                db_port = _config.port
                database = _config.schema

        self._login = login
        self._password = password
        self._host = host
        self._login = login
        self._password = password
        self._host = host
        self._url = url
        self._port = port
        self._public_key = public_key
        self._timeout = timeout
        self._db_login = db_login
        self._db_password = db_password
        self._db_host = db_host
        self._db_port = db_port
        self._database = database
        self._cert_root = cert_root
        self._cert_file = cert_file
        self._cert_key = cert_key
        self._base = base
        self._dry_run = dry_run
        self._log_level = log_level

        # Создание уникального имени для логов
        self._logger = logging.getLogger(self.__class__.__name__)

        # Добавляется хендлер только если его нет
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("[%(asctime)s] [%(levelname)s|%(name)s] %(message)s")
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.propagate = False

        self._logger.setLevel(log_level)  # Указание уровня логирования
        self._logger.debug(f"Создание экземпляра логгера {self.__class__.__name__}")

        self._param_conn = {k: v for k, v in
                            {'login': self._login, 'password': self._password, 'host': self._host, 'port': self._port,
                             'base': self._base, 'dry_run': self._dry_run, 'log_level': self._log_level}.items() if v}

        self._type_conn = None

        # Создание уникального имени для логов
        self._logger = logging.getLogger(self.__class__.__name__)

        # Добавляется хендлер только если его нет
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter("[%(asctime)s] [%(levelname)s|%(name)s] %(message)s")
            handler.setFormatter(formatter)
            self._logger.addHandler(handler)
            self._logger.propagate = False

        ### Выбор способа подключения
        # Если атрибуты, подходят для эндпоинтов Tentacula
        if all([self._url, self._login, self._password, self._host, self._cert_root, self._cert_file, self._cert_key]):
            self._type_conn = self.CONN_TENT
        # Если атрибуты, подходят для создания заданий в БД
        elif all([self._public_key, self._timeout, self._db_login, self._db_password, self._db_host, self._db_port,
                  self._database]):
            self._type_conn = self.CONN_DB
            self._db_table = 'ds_tasker'
            self._public_key = base64.b64decode(public_key.encode('utf-8'))
            self._public_key = serialization.load_pem_public_key(self._public_key)
        # Если указаны атрибуты, подходят для прямого доступа
        elif all([self._login, self._password, self._host]):
            self._type_conn = self.CONN_DS
        else:
            raise ValueError("Нет подходящего набора данных")

    def __enter__(self):
        """Автоматическое открытие сессии"""

        if self._type_conn == self.CONN_DS:
            self._connect_ds = DSHook(**self._param_conn).__enter__()
        elif self._type_conn == self.CONN_TENT:
            ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self._cert_root)
            ssl_ctx.load_cert_chain(certfile=self._cert_file, keyfile=self._cert_key)
            transport = httpx.HTTPTransport(verify=ssl_ctx)
            timeout = httpx.Timeout(connect=900, read=900, write=900, pool=900)
            self._connect_tent = httpx.Client(transport=transport, timeout=timeout)
        elif self._type_conn == self.CONN_DB:
            self._connect_db = psycopg2.connect(
                host=self._db_host,
                port=self._db_port,
                dbname=self._database,
                user=self._db_login,
                password=self._db_password
            )
        else:
            raise ValueError("Не удалось определить тип подключения")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Автоматическое закрытие сессии"""

        if self._type_conn == self.CONN_DS:
            self._connect_ds.__exit__(exc_type, exc_val, exc_tb)
        elif self._type_conn == self.CONN_TENT:
            self._connect_tent.close()
        elif self._type_conn == self.CONN_DB:
            self._connect_db.close()
        else:
            raise ValueError("Не удалось определить тип подключения")

    def query(self, type_query, param_query):
        if self._type_conn == self.CONN_DS:
            return getattr(self._connect_ds, type_query)(**param_query)
        if self._type_conn == self.CONN_TENT:
            url = f'{self._url}/ds/{type_query}'

            with open(self._cert_file, "rb") as f:
                cert_data = f.read()

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            self._logger.info(f"Run URL Connect: {url}"
                              f", Client cert Subject: 'CN={cn}'"
                              f", Client cert Serial: {cert.serial_number}")

            response = self._connect_tent.post(url, json={**self._param_conn, **param_query})
            try:
                response.raise_for_status()
                result = response.json()
                if result['error']:
                    raise RuntimeError(result['details'])
            except Exception as e:
                print(response.text)
                raise e

            return [DSDict(v) for v in datetime_parser(result)['details']]
        if self._type_conn == self.CONN_DB:
            return datetime_parser(
                request_db(
                    _connect=self._connect_db, db_table=self._db_table, timeout=self._timeout, type_query=type_query,
                    param_conn=self._param_conn, param_query=encode_param(self._public_key, param_query)
                )
            )
        else:
            raise ValueError("Не удалось определить тип подключения")

    def get_object(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree",
            type_object: DS_TYPE_OBJECT = "object"
    ) -> list[DSDict]:
        """
        Функция запроса любого объекта из каталога.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName (для user, group или computer) или словарь объекта DS (DSDict)). Не совместим с ldap_filter.
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity.
            properties: Запрос дополнительных атрибутов. Расширенные атрибуты: Enabled, PasswordNeverExpires, AccountNotDelegated (на основе userAccountControl), GroupScope, GroupCategory (на основе groupType), ChangePasswordAtLogon (на основе pwdLastSet).
            search_scope: Глубина поиска
            type_object: К фильтру поиска добавляется фильтр типа объекта ("object", "user", "group", "computer" или "contact")

        Returns:
            Список объектов из DS
        """

        type_query = 'get_object'
        param_query = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                         'search_scope': search_scope, 'type_object': type_object}.items() if
                       v is not None}

        return self.query(type_query, param_query)

    def get_user(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        """
        Функция запроса пользователя из каталога.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)). Не совместим с ldap_filter.
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity.
            properties: Запрос дополнительных атрибутов. Расширенные атрибуты: Enabled, PasswordNeverExpires, AccountNotDelegated (на основе userAccountControl), ChangePasswordAtLogon (на основе pwdLastSet).
            search_scope: Глубина поиска

        Returns:
            Список объектов из DS
        """

        type_query = 'get_user'
        param_query = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                         'search_scope': search_scope}.items() if v is not None}

        return self.query(type_query, param_query)

    def get_group(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        """
        Функция запроса компьютера из каталога DS.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)). Не совместим с ldap_filter.
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity.
            properties: Запрос дополнительных атрибутов. Расширенные атрибуты: Enabled, PasswordNeverExpires, AccountNotDelegated (на основе userAccountControl), ChangePasswordAtLogon (на основе pwdLastSet).
            search_scope: Глубина поиска

        Returns:
            Список объектов из DS
        """

        type_query = 'get_group'
        param_query = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                         'search_scope': search_scope}.items() if v is not None}

        return self.query(type_query, param_query)

    def get_computer(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        """
        Функция запроса компьютера из каталога DS.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)). Не совместим с ldap_filter.
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity.
            properties: Запрос дополнительных атрибутов. Расширенные атрибуты: Enabled, PasswordNeverExpires, AccountNotDelegated (на основе userAccountControl), ChangePasswordAtLogon (на основе pwdLastSet).
            search_scope: Глубина поиска

        Returns:
            Список объектов из DS
        """

        type_query = 'get_computer'
        param_query = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                         'search_scope': search_scope}.items() if v is not None}

        return self.query(type_query, param_query)

    def get_contact(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        """
        Функция запроса контактов из каталога DS.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)). Не совместим с ldap_filter.
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity.
            properties: Запрос дополнительных атрибутов. Расширенные атрибуты: GroupScope, GroupCategory (на основе groupType)
            search_scope: Глубина поиска

        Returns:
            Список объектов из DS
        """

        type_query = 'get_contact'
        param_query = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                         'search_scope': search_scope}.items() if v is not None}

        return self.query(type_query, param_query)

    def get_group_member(self, identity: str | DSDict) -> list[DSDict]:
        """
        Функция получения всех членов группы, с дополнительными атрибутами.

        Args:
            identity: Аргумент принимающий уникальные атрибуты группы для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).

        Returns:
            Список объектов из DS
        """

        type_query = 'get_group_member'
        param_query = {k: v for k, v in {'identity': identity}.items() if v is not None}

        return self.query(type_query, param_query)

    def set_object(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                   replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                   description: str = None) -> None:
        """
        Функция изменения атрибутов объекта в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты объекта для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict))
            remove: Удалить одно из значений в атрибуте
            add: Добавить значение в атрибут
            replace: Полная замена всех значений
            clear: Очистка в атрибуте
            display_name: Заполнение или изменение атрибута "displayName"
            description: Заполнение или изменение атрибута "description"
        """

        type_query = 'set_object'
        param_query = {k: v for k, v in
                       {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                        'display_name': display_name, 'description': description}.items() if v is not None}

        return self.query(type_query, param_query)

    def set_user(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                 replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                 description: str = None, sam_account_name: str = None, user_principal_name: str = None,
                 enabled: bool = None, password_never_expires: bool = None, account_not_delegated: bool = None,
                 change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None) -> None:
        """
        Функция изменения атрибутов пользователя в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты группы для идентификации  (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            remove: Удалить одно из значений в атрибуте.
            add: Добавить значение в атрибут.
            replace: Полная замена всех значений.
            clear: Очистка в атрибуте.
            display_name: Заполнение или изменение атрибута "displayName".
            description: Заполнение или изменение атрибута "description".
            sam_account_name: Заполнение или изменение атрибута "sAMAccountName".
            user_principal_name: Заполнение или изменение атрибута "userPrincipalName".
            enabled: Включение или отключение пользователя.
            password_never_expires: Включение или отключение бессрочного пароля.
            account_not_delegated: Включение или отключение запрета на делегирование.
            change_password_at_logon: Включение или отключение требования сменить пароль при входе.
            account_expiration_date: Указание или отключение срока действия пользователя.
        """

        type_query = 'set_user'
        param_query = {k: v for k, v in
                       {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                        'display_name': display_name, 'description': description, 'sam_account_name': sam_account_name,
                        'user_principal_name': user_principal_name, 'enabled': enabled,
                        'password_never_expires': password_never_expires,
                        'account_not_delegated': account_not_delegated,
                        'change_password_at_logon': change_password_at_logon,
                        'account_expiration_date': account_expiration_date}.items() if v is not None}

        return self.query(type_query, param_query)

    def set_group(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                  replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                  description: str = None, sam_account_name: str = None,
                  group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None) -> None:
        """
        Функция изменения атрибутов группы в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты группы для идентификации  (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            remove: Удалить одно из значений в атрибуте.
            add: Добавить значение в атрибут.
            replace: Полная замена всех значений.
            clear: Очистка в атрибуте.
            display_name: Заполнение или изменение атрибута "displayName".
            description: Заполнение или изменение атрибута "description".
            sam_account_name: Заполнение или изменение атрибута "sAMAccountName".
            group_scope: Изменение области работы группы.
            group_category: Изменение категории группы.
        """

        type_query = 'set_group'
        param_query = {k: v for k, v in
                       {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                        'display_name': display_name, 'description': description, 'sam_account_name': sam_account_name,
                        'group_scope': group_scope, 'group_category': group_category}.items() if v is not None}

        return self.query(type_query, param_query)

    def set_computer(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                     replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                     description: str = None) -> None:
        """
        Функция изменения атрибутов компьютера в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты компьютера для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            remove: Удалить одно из значений в атрибуте.
            add: Добавить значение в атрибут.
            replace: Полная замена всех значений.
            clear: Очистка в атрибуте.
            display_name: Заполнение или изменение атрибута "displayName".
            description: Заполнение или изменение атрибута "description".
        """

        type_query = 'set_computer'
        param_query = {k: v for k, v in
                       {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                        'display_name': display_name, 'description': description}.items() if v is not None}

        return self.query(type_query, param_query)

    def set_contact(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                    replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                    description: str = None) -> None:
        """
        Функция изменения атрибутов компьютера в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты контакта для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict))
            remove: Удалить одно из значений в атрибуте
            add: Добавить значение в атрибут
            replace: Полная замена всех значений
            clear: Очистка в атрибуте
            display_name: Заполнение или изменение атрибута "displayName"
            description: Заполнение или изменение атрибута "description"
        """

        type_query = 'set_contact'
        param_query = {k: v for k, v in
                       {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                        'display_name': display_name, 'description': description}.items() if v is not None}

        return self.query(type_query, param_query)

    def set_account_password(self, identity: str | DSDict, account_password: str) -> None:
        """
        Функция изменения пароля пользователя в DS. Принудительно снимает флаг "PASSWD_NOTREQD"

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            account_password: Новый пароль.
        """

        type_query = 'set_account_password'
        param_query = {k: v for k, v in {'identity': identity, 'account_password': account_password}.items() if
                       v is not None}

        return self.query(type_query, param_query)

    def set_account_unlock(self, identity: str | DSDict) -> None:
        """
        Функция снятия временной блокировки пользователя в DS (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации.
        """

        type_query = 'set_account_unlock'
        param_query = {k: v for k, v in {'identity': identity}.items() if v is not None}

        return self.query(type_query, param_query)

    def add_group_member(self, identity: str | DSDict,
                         members: str | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        """
        Функция добавления объектов в группу. Члены добавляются последовательно (один член, один запрос)

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            members: Аргумент принимающий уникальные атрибуты члена/членов группы (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
        """

        type_query = 'add_group_member'
        param_query = {k: v for k, v in {'identity': identity, 'members': members}.items() if v is not None}

        return self.query(type_query, param_query)

    def remove_group_member(self, identity: str | DSDict,
                            members: str | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        """
        Функция добавления объектов в группу. Члены удаляются последовательно (один член, один запрос)

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            members: Аргумент принимающий уникальные атрибуты члена/членов группы (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
        """

        type_query = 'remove_group_member'
        param_query = {k: v for k, v in {'identity': identity, 'members': members}.items() if v is not None}

        return self.query(type_query, param_query)

    def move_object(self, identity: str | DSDict, target_path: str) -> None:
        """
        Функция перемещения объектов между Организационными юнитами (изменяется distinguishedName).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
            target_path: Аргумент принимающий distinguishedName нового Организационного юнита
        """

        type_query = 'move_object'
        param_query = {k: v for k, v in {'identity': identity, 'target_path': target_path}.items() if v is not None}

        return self.query(type_query, param_query)

    def rename_object(self, identity: str | DSDict, new_name: str) -> None:
        """
        Функция переименования объекта (изменяются атрибуты cn, name и distinguishedName).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
            new_name: Аргумент принимающий новое имя
        """

        type_query = 'rename_object'
        param_query = {k: v for k, v in {'identity': identity, 'new_name': new_name}.items() if v is not None}

        return self.query(type_query, param_query)

    def new_user(self, path: str, name: str, sam_account_name: str, account_password: str, display_name: str = None,
                 user_principal_name: str = None, enabled: bool = None, password_never_expires: bool = None,
                 account_not_delegated: bool = None, change_password_at_logon: bool = None,
                 account_expiration_date: bool | datetime = None, other_attributes: dict[str, list] = None) -> None:
        """
            Функция создания объекта типа пользователь.

            Args:
                path: Организационный юнит создания объекта
                name: Имя объекта (формирует cn, name и часть distinguishedName)
                sam_account_name: sAMAccountName
                account_password: Пароль пользователя
                display_name: Выводимое имя пользователя (displayName)
                user_principal_name: userPrincipalName
                enabled: Указатель, включен ли объект
                password_never_expires: Указатель, является ли пароль бессрочным
                account_not_delegated: Указатель, что пользователь не может быть делегирован
                change_password_at_logon: Указатель, необходимости сменить пароль при входе
                account_expiration_date: Указывание даты исчезания пользователя, либо отключение параметра (False)
                other_attributes: Словарь с дополнительными атрибутами
            """

        type_query = 'new_user'
        param_query = {k: v for k, v in {'path': path, 'name': name, 'sam_account_name': sam_account_name,
                                         'account_password': account_password, 'display_name': display_name,
                                         'user_principal_name': user_principal_name, 'enabled': enabled,
                                         'password_never_expires': password_never_expires,
                                         'account_not_delegated': account_not_delegated,
                                         'change_password_at_logon': change_password_at_logon,
                                         'account_expiration_date': account_expiration_date,
                                         'other_attributes': other_attributes}.items() if v is not None}

        return self.query(type_query, param_query)

    def new_group(self, path: str, name: str, sam_account_name: str, display_name: str = None,
                  group_scope: DS_GROUP_SCOPE = 'Global', group_category: DS_GROUP_CATEGORY = 'Security',
                  other_attributes: dict[str, list] = None) -> None:
        """
            Функция создания объекта типа группа.

            Args:
                path: Организационный юнит создания объекта
                name: Имя объекта (формирует cn, name и часть distinguishedName)
                sam_account_name: sAMAccountName
                display_name: Выводимое имя пользователя (displayName)
                group_scope: Указатель области группы ("DomainLocal", "Global" (по умолчанию) или "Universal")
                group_category: Указатель категории группы ("Security" (по умолчанию) или "Distribution")
                other_attributes: Словарь с дополнительными атрибутами
        """

        type_query = 'new_group'
        param_query = {k: v for k, v in
                       {'path': path, 'name': name, 'sam_account_name': sam_account_name, 'display_name': display_name,
                        'group_scope': group_scope, 'group_category': group_category,
                        'other_attributes': other_attributes}.items() if v is not None}

        return self.query(type_query, param_query)

    def new_contact(self, path: str, name: str, display_name: str = None,
                    other_attributes: dict[str, list] = None) -> None:
        """
            Функция создания объекта типа контакт.

            Args:
                path: Организационный юнит создания объекта
                name: Имя объекта (формирует cn, name и часть distinguishedName)
                display_name: Выводимое имя пользователя (displayName)
                other_attributes: Словарь с дополнительными атрибутами
        """

        type_query = 'new_contact'
        param_query = {k: v for k, v in {'path': path, 'name': name, 'display_name': display_name,
                                         'other_attributes': other_attributes}.items() if v is not None}

        return self.query(type_query, param_query)

    def remove_object(self, identity: str | DSDict, type_object: DS_TYPE_OBJECT = "object") -> None:
        """
            Функция удаления объекта.

            Args:
                identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
                type_object: К фильтру поиска добавляется фильтр типа объекта ("object", "user", "group", "computer" или "contact")
        """

        type_query = 'remove_object'
        param_query = {k: v for k, v in {'identity': identity, 'type_object': type_object}.items() if v is not None}

        return self.query(type_query, param_query)

    def remove_user(self, identity: str | DSDict) -> None:
        """
            Функция удаления объекта типа пользователь.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """

        type_query = 'remove_user'
        param_query = {k: v for k, v in {'identity': identity}.items() if v is not None}

        return self.query(type_query, param_query)

    def remove_group(self, identity: str | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """

        type_query = 'remove_group'
        param_query = {k: v for k, v in {'identity': identity}.items() if v is not None}

        return self.query(type_query, param_query)

    def remove_computer(self, identity: str | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """

        type_query = 'remove_computer'
        param_query = {k: v for k, v in {'identity': identity}.items() if v is not None}

        return self.query(type_query, param_query)

    def remove_contact(self, identity: str | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict))
        """

        type_query = 'remove_contact'
        param_query = {k: v for k, v in {'identity': identity}.items() if v is not None}

        return self.query(type_query, param_query)
