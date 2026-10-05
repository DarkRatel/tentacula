import os
import json
import logging
import time
import base64
from copy import copy
from datetime import datetime, timedelta

import httpx, ssl
import psycopg2
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

from app.ds import DSHook, DSDict, Event
from app.ds import DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY


class MergingLoggerAdapter(logging.LoggerAdapter):
    """Функция для объединения расширенных переменных из адаптера и строки события, для совместимости с Python ≤ 3.12"""

    def process(self, msg, kwargs):
        kwargs["extra"] = {
            **self.extra,
            **kwargs.get("extra", {}),
        }
        return msg, kwargs


def mask_protect_data(value: dict, hide_pass: bool = True) -> dict:
    """Функция преобразования данных и маскирования значений у ключей с упоминанием слова password"""
    for k, v in value.items():
        if isinstance(v, str):
            if hide_pass and 'password' in k.lower():
                value.update({k: '***'})
        elif isinstance(v, dict):
            value.update({k: encode_value(v)})
        else:
            value.update({k: v})

    return value


def decode_value(value):
    """Функция конвертации даты полученной в виде строки в datetime"""
    if isinstance(value, str):
        if value.startswith("hex:"):
            return bytes.fromhex(value.lstrip("hex:"))
        try:
            # Если в строке есть прочерк, предполагается, что строка может быть датой в формате ISO,
            # поэтому производится попытка конвертации.
            # Если получена ошибка конвертации, возвращается оригинальное значение
            return datetime.fromisoformat(value) if '-' in value else value
        except ValueError:
            return value
    if isinstance(value, list):
        return [decode_value(i) for i in value]
    if isinstance(value, dict):
        for k, v in value.items():
            value[k] = decode_value(v)
        return value
    return value


def encode_value(value):
    """Функция конвертации datetime в строку в формате ISO"""
    if isinstance(value, bytes):
        return f"hex:{value.hex()}"
    if isinstance(value, datetime):
        try:
            return datetime.isoformat(value)
        except ValueError:
            return value
    elif isinstance(value, list):
        return [encode_value(i) for i in value]
    elif isinstance(value, dict):
        for k, v in value.items():
            value[k] = encode_value(v)
        return value
    return value


def encode_param(_public_key, param: dict):
    """
    Функция шифрования открытым ключом словаря. Актуально для обращений через таблицу заданий и Шедуллер

    Args:
        _public_key: Функция открытого ключа
        param: Шифруемый словарь
    """
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


def request_db(_connect, _logger: logging.LoggerAdapter, db_table: str, timeout: int, pre_execution_delay: int,
               execution_delay: int, type_query, param_conn, param_query):
    """
    Функция формирования задания для таблицы и получения ответа.
    Актуально для обращений через таблицу заданий и Шедуллер

    Args:
        _connect: Открытая сессия с БД
        _logger: Функция логирования
        db_table: Название таблицы для отправки заданий
        timeout: Максимальное время ожидания ответа в таблице
        type_query: Тип запроса к СК
        param_conn: Параметры подключения к СК
        param_query: Параметры запроса
        pre_execution_delay: Время паузы между опросом БД на получение результата, когда задание ещё не взято в работу
        execution_delay: Время паузы между опросом БД на получение результата, когда задание исполняется
    """

    # Отправка запроса в таблицу
    with _connect:
        with _connect.cursor() as cur:
            cur.execute(
                f"INSERT INTO {db_table} (status, type_query, param_conn, param_query)"
                f" VALUES ('waiting', '{type_query}', '{param_conn}', '{param_query}') RETURNING id"
            )
            query_id = cur.fetchone()[0]
            _logger.info({'msg': 'DS Task', 'id': query_id}, extra={'e_id': Event.TENT_QUERY_ID})

    dt_start = datetime.now()
    dt_timeout = dt_start + timedelta(seconds=timeout)

    # В переменную выписывается время задержки для паузы между запросами
    pause_sec = pre_execution_delay

    # Проверка получения ответа
    with _connect:
        with _connect.cursor() as cur:

            while True:
                # Пауза перед повторной проверкой
                time.sleep(pause_sec)

                # Запрос статуса и результата из задания
                cur.execute(f"SELECT status, result FROM {db_table} WHERE id = {query_id}")
                # Получение результата
                result = cur.fetchone()

                # Если результат запроса был получен
                if isinstance(result, tuple):
                    # Если задание перешло в статусы связанные с его исполнением на Tentacula, время паузы обновляется
                    if result[0] in ['working', 'in_line']:
                        pause_sec = execution_delay

                    if result[0] == 'error':
                        cur.execute(f"DELETE FROM {db_table} WHERE id = {query_id}")
                        cur.connection.commit()

                        raise RuntimeError(result[1])

                    if result[0] == 'complete':
                        cur.execute(f"DELETE FROM {db_table} WHERE id = {query_id}")
                        cur.connection.commit()

                        if isinstance(result[1], list):
                            return [DSDict(i) for i in result[1]]
                        return result[1]
                else:
                    raise RuntimeError("В таблице не найдено задание")

                # Если время вышло, процесс ожидания прерывается
                if datetime.now() > dt_timeout:
                    raise TimeoutError("Время ожидания выполнения запроса истекло")


def locals_value(data: dict) -> dict:
    """Функция убирающая self из запроса и незаданные значения"""
    return {k: v for k, v in data.items() if v is not None and k != 'self'}


class SDSHook:
    # Указатели какой тип подключения будет использоваться
    CONN_DS = 1
    CONN_TENT = 2
    CONN_DB = 3

    def __init__(self, login: str = None, password: str = None, host: str | list[str] = None, port: int = 636,
                 base: str = None, dry_run: bool = False, log_level: int = None, public_key: str = None,
                 timeout: int = 180, db_login: str = None, db_password: str = None, db_host: str = None,
                 db_port: int = 5432, database: str = None, db_pre_execution_delay: float = 0.1,
                 db_execution_delay: float = 0.1, url: str | list = None, cert_root: str = None, cert_file: str = None,
                 cert_key: str = None, tent_login: str = None, tent_pass: str = None, airflow_conn_id: str = None,
                 airflow_conn=None) -> None:
        """
        Класс создаёт сессию с DS, в рамках который будет исполнен запрос к каталогу
        (запрос описывается в рамках наследованных функций).
        Хук объединяет в себе три способа взаимодействия c DS:
            1. Через DS эндпоинты Тентакли (минимальные атрибуты: url, login, password, host);
            2. Через DS шедуллер (минимальные атрибуты: public_key, db_login, db_password, db_host, db_port, database)
            3. Напрямую к DS (login, password, host);

        Args:
            login: Логин учётной записи, от имени который создаётся сессия в DS
            password: Пароль от учётной записи
            host: Адрес контроллера домена
            port: Порт подключения: 389 или 636 (по умолчанию 636)
            base: Область каталога. Если не указать, при открытии сессии у DS будет запрошена область работы
            dry_run: Формирование запроса, без внесения изменений в DS
            log_level: Тип логирования (принимает значения от logging)
            public_key: Публичный ключ для шифрования данных запросов отправленных в таблицу БД
            timeout: Время ожидания ответа от сБД в секундах
            db_login: Логин для доступа к БД
            db_password: Пароль для доступа к БД
            db_host: Хост БД
            db_port: Порт БД
            database: Имя БД
            db_pre_execution_delay: Время паузы в секундах между опросом БД на получение результата, когда задание ещё не взято в работу
            db_execution_delay: Время паузы в секундах между опросом БД на получение результата, когда задание исполняется
            url: Адрес Тентакли
            cert_root: Путь до корневого сертификата
            cert_file: Путь до клиентского сертификата
            cert_key: Путь до закрытого ключа клиентского сертификата
            airflow_conn_id: ID-подключения из Apache Airflow
            airflow_conn: Выгруженное подключение из Apache Airflow
            tent_login: Логин для авторизации на эндпоинте Тентакли
            tent_pass: Пароль для авторизации на эндпоинте Тентакли
        """

        # Если все ключи переданы через Airflow
        if any([airflow_conn_id, airflow_conn]):
            if airflow_conn_id:
                from airflow.hooks.base_hook import BaseHook
                _config = BaseHook.get_connection(airflow_conn_id)
            else:
                _config = airflow_conn

            login = login or _config.login
            password = password or _config.password
            host = host or _config.host
            port = port or _config.port
            base = base or _config.schema

            # Дополнительные комментарии запрашиваются из Extra
            if _config.get_extra():
                _data = json.loads(_config.get_extra())
                url = url or _data.get("url", None)
                public_key = public_key or _data.get("public_key", None)

                cert_root = cert_root or _data.get("cert_root", None)
                cert_file = cert_file or _data.get("cert_file", None)
                cert_key = cert_key or _data.get("cert_key", None)
                dry_run = dry_run or _data.get("dry_run", False)
                log_level = log_level or _data.get("log_level", None)
                timeout = timeout or _data.get("timeout", None)
                db_pre_execution_delay = db_pre_execution_delay or _data.get("db_pre_execution_delay", None)
                db_execution_delay = db_execution_delay or _data.get("db_execution_delay", None)

                db_login = db_login or _data.get("db_login", None)
                db_password = db_password or _data.get("db_password", None)
                db_host = db_host or _data.get("db_host", None)
                db_port = db_port or _data.get("db_port", None)
                database = database or _data.get("database", None)

                # Получение подключения к БД, если необходимо использовать
                db_conn_id = _data.get("db_conn_id", None)
                if db_conn_id:
                    _config = BaseHook.get_connection(db_conn_id)
                    db_login = db_login or _config.login
                    db_password = db_password or _config.password
                    db_host = db_host or _config.host
                    db_port = db_port or _config.port
                    database = database or _config.schema

                # Получение подключения к Тентакле
                tent_conn_id = _data.get("tent_conn_id", None)
                if tent_conn_id:
                    _config = BaseHook.get_connection(tent_conn_id)
                    tent_login = tent_login or _config.login
                    tent_pass = tent_pass or _config.password

        self._login = login
        self._password = password
        self._host = host
        self._url = url.split(',') if isinstance(url, str) else url
        self._port = port
        self._public_key = public_key
        self._timeout = timeout
        self._db_login = db_login
        self._db_password = db_password
        self._db_host = db_host
        self._db_port = db_port
        self._db_pre_execution_delay = db_pre_execution_delay
        self._db_execution_delay = db_execution_delay
        self._database = database
        self._cert_root = cert_root
        self._cert_file = cert_file
        self._cert_key = cert_key
        self.base = base
        self._dry_run = dry_run
        self._log_level = log_level
        self._tent_login = tent_login
        self._tent_pass = tent_pass

        # Создание уникального имени для логов
        self._logger = MergingLoggerAdapter(logging.getLogger(self.__class__.__name__), extra={"u_id": self._login})
        self._logger.setLevel(log_level or logging.INFO)

        self._param_conn = {k: v for k, v in
                            {'login': self._login, 'password': self._password, 'host': self._host, 'port': self._port,
                             'base': self.base, 'dry_run': self._dry_run, 'log_level': self._log_level,
                             'tent_login': self._tent_login, 'tent_pass': self._tent_pass}.items() if v is not None}
        self._type_conn = None

        ### Выбор способа подключения
        # Если атрибуты, подходят для эндпоинтов Tentacula
        if all([self._url, self._login, self._password, self._host]):
            self._type_conn = self.CONN_TENT
        # Если атрибуты, подходят для создания заданий в БД
        elif all([self._public_key, self._db_login, self._db_password, self._db_host, self._db_port, self._database]):
            self._type_conn = self.CONN_DB
            self._db_table = 'tentacula_ds_tasker'
            self._public_key = base64.b64decode(public_key.encode('utf-8'))
            self._public_key = serialization.load_pem_public_key(self._public_key)
        # Если указаны атрибуты, подходят для прямого доступа
        elif all([self._login, self._password, self._host]):
            self._type_conn = self.CONN_DS
        else:
            raise ValueError("В запросе не указан минимальный набор ключей ни для одного типа запроса")

    def __enter__(self):
        """Автоматическое открытие сессии"""

        if self._type_conn == self.CONN_DS:
            self._connect_ds = DSHook(**self._param_conn).__enter__()
        elif self._type_conn == self.CONN_TENT:
            # Если не переданы параметры для HTTP запроса сопровождающего сертификатом,
            # будет попытка открыть соединение без них
            if all([self._cert_root, self._cert_file, self._cert_key]):
                ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self._cert_root)
                ssl_ctx.load_cert_chain(certfile=self._cert_file, keyfile=self._cert_key)
                transport = httpx.HTTPTransport(verify=ssl_ctx)
            else:
                transport = httpx.HTTPTransport()
            timeout = httpx.Timeout(connect=10, read=32, write=32, pool=10)
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

    def _query(self, type_query, param_query):
        """
        Функция отправки запросов через целевой метод

        Args:
            type_query: Тип операции
            param_query: Параметры операции
        """

        # Прямое обращение к СК
        if self._type_conn == self.CONN_DS:
            # В подключение прямого обращение к DS, передаётся переменная base, если была переназначена
            if self.base and self._connect_ds.base != self.base:
                self._connect_ds.base = self.base
            return getattr(self._connect_ds, type_query)(**param_query)

        # Для всех альтернативных доступов base назначенный через переменную передаётся в запрос
        if self.base and self._param_conn.get('base') != self.base:
            self._param_conn['base'] = self.base

        # copy используется, чтобы не изменилось оригинальное значение при формировании строки подходящей для логов
        self._logger.info({'msg': 'Tent query', 'endpoint': type_query,
                           'conn_params': mask_protect_data(copy(self._param_conn), hide_pass=True),
                           'query_params': mask_protect_data(copy(param_query), hide_pass=True)},
                          extra={'e_id': Event.TENT_QUERY_PARAM})

        # Обращение к СК через Тентаклю
        if self._type_conn == self.CONN_TENT:
            # Перебор полученного списка Тентаклей, для поиска доступной
            for url in self._url:
                try:
                    url = f'{url}/{type_query}'

                    auth_data = {'msg': 'Query to endpoint', 'url': url}

                    # Если был указан сертификат для подключения, его данные будут добавлены в логи
                    if self._cert_file:
                        with open(self._cert_file, "rb") as f:
                            cert_data = f.read()

                        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                        auth_data.update({'cn': cn, 'serial': cert.serial_number})

                    # Если был указан логин для авторизации на Тентакле
                    if self._tent_login:
                        auth_data.update({'tent_login': self._tent_login})

                    self._logger.info(auth_data, extra={'e_id': Event.TENT_QUERY_ENDPOINT})

                    response = self._connect_tent.post(url, json={
                        **mask_protect_data(self._param_conn, hide_pass=False),
                        **mask_protect_data(param_query, hide_pass=False)
                    })

                    break
                except httpx.ConnectError as e:
                    self._logger.warning(f"Host {url}: {e}", extra={'e_id': Event.TENT_ENDPOINT_ERROR})

            else:
                raise TimeoutError(f"Can't contact HTTP servers")

            # Проверка полученных результатов
            try:
                response.raise_for_status()
                result = response.json()
                if result['error']:
                    raise RuntimeError(result['details'])
            except Exception as e:
                self._logger.warning(response.text, extra={'e_id': Event.TENT_ENDPOINT_ERROR_ANSWER})
                raise e

            if isinstance(result['details'], list):
                return [DSDict(decode_value(v)) if isinstance(v, dict) else v for v in result['details']]
            else:
                return result['details']

        # Обращение к СК через Шедуллер
        if self._type_conn == self.CONN_DB:
            return decode_value(request_db(
                _connect=self._connect_db, _logger=self._logger, db_table=self._db_table,
                timeout=self._timeout, type_query=type_query,
                param_conn=encode_param(self._public_key, mask_protect_data(self._param_conn, hide_pass=False)),
                param_query=encode_param(self._public_key, mask_protect_data(param_query, hide_pass=False)),
                pre_execution_delay=self._db_pre_execution_delay, execution_delay=self._db_execution_delay
            ))
        else:
            raise ValueError("Не удалось определить тип подключения")

    def get_root_dse(self, ldap_filter: str = '(objectClass=*)', properties: str | list | tuple = '*') -> list:
        """
        Функция запроса данных корня домена

        Args:
            ldap_filter: Аргумент для поиска по LDAP-фильтру
            properties: properties: Запрос дополнительных атрибутов. '*' возвращает все заполненные атрибуты
        """
        return self._query('get_root_dse', locals_value(locals()))

    def get_object(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = None,
            type_object: DS_TYPE_OBJECT = None, result_set_size: int | None = None, range_on: bool = None
    ) -> list[DSDict]:
        """
        Функция запроса любого объекта из каталога.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName (для user, group или computer) или словарь объекта DS (DSDict)). Не совместим с ldap_filter. Возвращает ошибку, если не будет получен один объект
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity
            properties: Запрос дополнительных атрибутов. '*' возвращает все заполненные атрибуты. Расширенные атрибуты: Enabled, PasswordNeverExpires, AccountNotDelegated (на основе userAccountControl), GroupScope (на основе groupType), GroupCategory (на основе groupType), ChangePasswordAtLogon (на основе pwdLastSet), FlagsUAC (флаги из атрибута userAccountControl), FlagsGT (флаги из атрибута groupType)
            search_scope: Глубина поиска
            type_object: К фильтру поиска добавляется фильтр типа объекта  ("object", "user", "group", "computer" или "contact") (по умолчанию)
            result_set_size: Ограничение на число объектов, которые должно быть возвращено (Если None ограничений нет)
            range_on: Параметр включающий запрос всех значений из атрибутов с большим количеством элементов

        Returns:
            Список объектов из DS
        """
        return self._query('get_object', locals_value(locals()))

    def get_user(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = None,
            result_set_size: int | None = None, range_on: bool = None
    ) -> list[DSDict]:
        """
        Функция запроса пользователя из каталога.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)). Не совместим с ldap_filter. Возвращает ошибку, если не будет получен один объект
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity
            properties: Запрос дополнительных атрибутов. '*' возвращает все заполненные атрибуты. Расширенные атрибуты: Enabled, PasswordNeverExpires, AccountNotDelegated (на основе userAccountControl), ChangePasswordAtLogon (на основе pwdLastSet), FlagsUAC (флаги из атрибута userAccountControl)
            search_scope: Глубина поиска
            result_set_size: Ограничение на число объектов, которые должно быть возвращено (Если None ограничений нет)
            range_on: Параметр включающий запрос всех значений из атрибутов с большим количеством элементов

        Returns:
            Список объектов из DS
        """
        return self._query('get_user', locals_value(locals()))

    def get_group(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = None,
            result_set_size: int | None = None, range_on: bool = None
    ) -> list[DSDict]:
        """
        Функция запроса компьютера из каталога DS.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)). Не совместим с ldap_filter. Возвращает ошибку, если не будет получен один объект
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity
            properties: Запрос дополнительных атрибутов. '*' возвращает все заполненные атрибуты. Расширенные атрибуты: GroupScope (на основе groupType), GroupCategory (на основе groupType), FlagsGT (флаги из атрибута groupType)
            search_scope: Глубина поиска
            result_set_size: Ограничение на число объектов, которые должно быть возвращено (Если None ограничений нет)
            range_on: Параметр включающий запрос всех значений из атрибутов с большим количеством элементов

        Returns:
            Список объектов из DS
        """
        return self._query('get_group', locals_value(locals()))

    def get_computer(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = None,
            result_set_size: int | None = None, range_on: bool = None
    ) -> list[DSDict]:
        """
        Функция запроса компьютера из каталога DS.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName (для user, group или computer) или словарь объекта DS (DSDict)). Не совместим с ldap_filter. Возвращает ошибку, если не будет получен один объект
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity
            properties: Запрос дополнительных атрибутов. '*' возвращает все заполненные атрибуты. Расширенные атрибуты: Enabled, PasswordNeverExpires, AccountNotDelegated (на основе userAccountControl), ChangePasswordAtLogon (на основе pwdLastSet), FlagsUAC (флаги из атрибута userAccountControl)
            search_scope: Глубина поиска
            result_set_size: Ограничение на число объектов, которые должно быть возвращено (Если None ограничений нет)
            range_on: Параметр включающий запрос всех значений из атрибутов с большим количеством элементов

        Returns:
            Список объектов из DS
        """
        return self._query('get_computer', locals_value(locals()))

    def get_contact(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = None,
            result_set_size: int | None = None, range_on: bool = None
    ) -> list[DSDict]:
        """
        Функция запроса контактов из каталога DS.

        Args:
            identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID или словарь объекта DS (DSDict)). Не совместим с ldap_filter. Возвращает ошибку, если не будет получен один объект
            ldap_filter: Аргумент для поиска по LDAP-фильтру. Не совместим с identity
            properties: Запрос дополнительных атрибутов. '*' возвращает все заполненные атрибуты
            search_scope: Глубина поиска
            result_set_size: Ограничение на число объектов, которые должно быть возвращено (Если None ограничений нет)
            range_on: Параметр включающий запрос всех значений из атрибутов с большим количеством элементов

        Returns:
            Список объектов из DS
        """
        return self._query('get_contact', locals_value(locals()))

    def get_group_member(self, identity: str | dict | DSDict) -> list[DSDict]:
        """
        Функция получения всех членов группы, с дополнительными атрибутами.
        Если передан DSDict группы, поиск группы не будет производиться.

        Args:
            identity: Аргумент принимающий уникальные атрибуты группы для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).

        Returns:
            Список объектов из DS
        """
        return self._query('get_group_member', locals_value(locals()))

    def set_object(self, identity: str | dict | DSDict,
                   remove: dict[str, list | bool | str] = None, add: dict[str, list | bool | str] = None,
                   replace: dict[str, list | bool | str] = None, clear: list[str] = None,
                   display_name: str = None, description: str = None) -> None:
        """
        Функция изменения атрибутов объекта в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты объекта для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName (для user, group или computer) или словарь объекта DS (DSDict))
            remove: Удалить одно из значений в атрибуте
            add: Добавить значение в атрибут
            replace: Полная замена всех значений
            clear: Очистка атрибута
            display_name: Заполнение или изменение атрибута "displayName"
            description: Заполнение или изменение атрибута "description"
        """
        return self._query('set_object', locals_value(locals()))

    def set_user(self, identity: str | dict | DSDict,
                 remove: dict[str, list | bool | str] = None, add: dict[str, list | bool | str] = None,
                 replace: dict[str, list | bool | str] = None, clear: list[str] = None,
                 display_name: str = None, description: str = None, sam_account_name: str = None,
                 user_principal_name: str = None, enabled: bool = None, password_never_expires: bool = None,
                 account_not_delegated: bool = None, change_password_at_logon: bool = None,
                 account_expiration_date: bool | datetime | str = None) -> None:
        """
        Функция изменения атрибутов пользователя в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты группы для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            remove: Удалить одно из значений в атрибуте.
            add: Добавить значение в атрибут.
            replace: Полная замена всех значений.
            clear: Очистка атрибута.
            display_name: Заполнение или изменение атрибута "displayName".
            description: Заполнение или изменение атрибута "description".
            sam_account_name: Заполнение или изменение атрибута "sAMAccountName".
            user_principal_name: Заполнение или изменение атрибута "userPrincipalName".
            enabled: Включение или отключение пользователя.
            password_never_expires: Включение или отключение бессрочного пароля.
            account_not_delegated: Включение или отключение запрета на делегирование.
            change_password_at_logon: Включение или отключение требования сменить пароль при входе.
            account_expiration_date: Указание даты или отключение срока действия пользователя.
        """
        return self._query('set_user', locals_value(locals()))

    def set_group(self, identity: str | dict | DSDict,
                  remove: dict[str, list | bool | str] = None, add: dict[str, list | bool | str] = None,
                  replace: dict[str, list | bool | str] = None, clear: list[str] = None,
                  display_name: str = None, description: str = None, sam_account_name: str = None,
                  group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None) -> None:
        """
        Функция изменения атрибутов группы в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты группы для идентификации  (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            remove: Удалить одно из значений в атрибуте.
            add: Добавить значение в атрибут.
            replace: Полная замена всех значений.
            clear: Очистка атрибута.
            display_name: Заполнение или изменение атрибута "displayName".
            description: Заполнение или изменение атрибута "description".
            sam_account_name: Заполнение или изменение атрибута "sAMAccountName".
            group_scope: Изменение области работы группы.
            group_category: Изменение категории группы.
        """
        return self._query('set_group', locals_value(locals()))

    def set_computer(self, identity: str | dict | DSDict,
                     remove: dict[str, list | bool | str] = None, add: dict[str, list | bool | str] = None,
                     replace: dict[str, list | bool | str] = None, clear: list[str] = None,
                     display_name: str = None, description: str = None) -> None:
        """
        Функция изменения атрибутов компьютера в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты компьютера для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            remove: Удалить одно из значений в атрибуте.
            add: Добавить значение в атрибут.
            replace: Полная замена всех значений.
            clear: Очистка атрибута.
            display_name: Заполнение или изменение атрибута "displayName".
            description: Заполнение или изменение атрибута "description".
        """
        return self._query('set_computer', locals_value(locals()))

    def set_contact(self, identity: str | dict | DSDict,
                    remove: dict[str, list | bool | str] = None, add: dict[str, list | bool | str] = None,
                    replace: dict[str, list | bool | str] = None, clear: list[str] = None,
                    display_name: str = None, description: str = None) -> None:
        """
        Функция изменения атрибутов компьютера в DS.

        Args:
            identity: Аргумент принимающий уникальные атрибуты контакта для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict))
            remove: Удалить одно из значений в атрибуте
            add: Добавить значение в атрибут
            replace: Полная замена всех значений
            clear: Очистка атрибута
            display_name: Заполнение или изменение атрибута "displayName"
            description: Заполнение или изменение атрибута "description"
        """
        return self._query('set_contact', locals_value(locals()))

    def set_account_password(self, identity: str | dict | DSDict, account_password: str) -> None:
        """
        Функция изменения пароля пользователя в DS. Принудительно снимает флаг "PASSWD_NOTREQD"

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            account_password: Новый пароль.
        """
        return self._query('set_account_password', locals_value(locals()))

    def set_account_unlock(self, identity: str | dict | DSDict) -> None:
        """
        Функция снятия временной блокировки пользователя в DS (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации.
        """
        return self._query('set_account_unlock', locals_value(locals()))

    def add_group_member(self, identity: str | dict | DSDict,
                         members: str | dict | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        """
        Функция добавления объектов в группу. Члены добавляются последовательно (один член, один запрос)

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            members: Аргумент принимающий уникальные атрибуты члена/членов группы (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
        """
        return self._query('add_group_member', locals_value(locals()))

    def remove_group_member(self, identity: str | dict | DSDict,
                            members: str | dict | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        """
        Функция добавления объектов в группу. Члены удаляются последовательно (один член, один запрос)

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            members: Аргумент принимающий уникальные атрибуты члена/членов группы (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
        """
        return self._query('remove_group_member', locals_value(locals()))

    def move_object(self, identity: str | dict | DSDict, target_path: str) -> None:
        """
        Функция перемещения объектов между Организационными юнитами (изменяется distinguishedName).
        Оригинальный CN в distinguishedName сохраняется

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
            target_path: Аргумент принимающий distinguishedName нового Организационного юнита
        """
        return self._query('move_object', locals_value(locals()))

    def rename_object(self, identity: str | dict | DSDict, new_name: str) -> None:
        """
        Функция переименования объекта (изменяются атрибуты cn, name и distinguishedName).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
            new_name: Аргумент принимающий новое имя
        """
        return self._query('rename_object', locals_value(locals()))

    def new_user(self, path: str, name: str, sam_account_name: str, account_password: str, display_name: str = None,
                 user_principal_name: str = None, enabled: bool = None, password_never_expires: bool = None,
                 account_not_delegated: bool = None, change_password_at_logon: bool = None,
                 account_expiration_date: bool | datetime | str = None,
                 other_attributes: dict[str, list] = None) -> None:
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
        return self._query('new_user', locals_value(locals()))

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
        return self._query('new_group', locals_value(locals()))

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
        return self._query('new_contact', locals_value(locals()))

    def remove_object(self, identity: str | dict | DSDict, type_object: DS_TYPE_OBJECT = None) -> None:
        """
            Функция удаления объекта.

            Args:
                identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
                type_object: К фильтру поиска добавляется фильтр типа объекта ("object", "user", "group", "computer" или "contact")
        """
        return self._query('remove_object', locals_value(locals()))

    def remove_user(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа пользователь.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """
        return self._query('remove_user', locals_value(locals()))

    def remove_group(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """
        return self._query('remove_group', locals_value(locals()))

    def remove_computer(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """
        return self._query('remove_computer', locals_value(locals()))

    def remove_contact(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict))
        """
        return self._query('remove_contact', locals_value(locals()))
