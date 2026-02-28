import os
import subprocess
import logging
from datetime import datetime

import ldap
import ldap.sasl

from .ds_dict import DSDict
from .data import DataDSProperties, DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY
from .func_ds_get import search_object, gen_filter_to_id
from .ds_function import search_root_dse
from .convertors_value import UAC_FLAGS
from .func_general import gen_uac, gen_gt, gen_change_pwd_at_logon, gen_account_exp_date
from .func_ds_new import ds_new
from .func_ds_set import ds_set
from .func_ds_set_member import ds_set_member

prefix_ldap = {
    636: 'ldaps',
    389: 'ldap'
}


def kinit_keytab(login: str, keytab: str):
    # os.environ["KRB5CCNAME"] = cache
    # , cache: str = None
    os.environ["KRB5_CLIENT_KTNAME"] = keytab
    subprocess.run(
        ["kinit", "-k", "-t", keytab, login],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


class DSHook:
    def __init__(self, host: str | list, login: str, password: str = None, keytab: str = None,
                 port: int = 636, base: str = None,
                 dry_run: bool = False, log_level: int = None) -> None:
        """
        Класс создаёт сессию с DS, в рамках который будет исполнен запрос к каталогу
        (запрос описывается в рамках наследованных функций).
        Последовательность авторизации:
        1. Если указан "password", будет попытка авторизация по паролю;
        2. Если указан "keytab", будет попытка запросить билеты на основе файла;
        3. Если не указан "password" и "keytab", будет попытка использовать билеты Kerberos из текущей сессии

        Args:
            login: Логин учётной записи, от имени который создаётся сессия в DS
            (для билетов Kerberos (Keytab) требуется userPrincipalName с доменом заглавными буквами)
            password: Пароль от учётной записи
            keytab: Путь до Keytab-файла Если требуется запросить keytab
            host: Адрес контроллера домена (если в строке будут указаны хосты через запятую или передан список хостов,
            хук будет последовательно подключается к следующему, если предыдущий будет недоступен)
            port: Порт подключения: 389 или 636 (по умолчанию 636)
            base: Область каталога. Если не указать, при открытии сессии у DS будет запрошена область работы
            (при определении зоны поиска автоматически исключает DomainDnsZones, ForestDnsZones)
            dry_run: Формирование запроса, без внесения изменений в DS
            log_level: Переопределение глубины логирования
        """

        self.dry_run = dry_run

        self._login = login
        self._password = password
        self._keytab = keytab

        self.base = base
        self._host = host.split(',') if isinstance(host, str) else host
        self._port = port
        if not prefix_ldap.get(port):
            raise ValueError("Only 636 or 389 ports are allowed")

        # Создание уникального имени для логов
        self._logger = logging.getLogger(self.__class__.__name__)

        if log_level:
            self._logger.setLevel(log_level)

    def __enter__(self):
        """Автоматическое открытие сессии"""

        connect_line = None

        for host in self._host:
            try:
                connect_line = f"{prefix_ldap[self._port]}://{host}:{self._port}"

                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
                self._connect = ldap.initialize(connect_line)

                self._connect.set_option(ldap.OPT_REFERRALS, 0)
                self._connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
                self._connect.set_option(ldap.OPT_DEBUG_LEVEL, 255)
                self._connect.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

                self._logger.info(f"Run LDAP Connect: {connect_line}, login: {self._login}")

                # Запрос выпуска билетов на основе Keytab
                if self._keytab:
                    kinit_keytab(login=self._login, keytab=self._keytab)

                if self._password:  # Открытие сессии с DS по паролю
                    self._connect.simple_bind_s(self._login, self._password)
                else:
                    self._connect.sasl_interactive_bind_s("", ldap.sasl.gssapi())  # Открытие сессии с DS по Keytab

                break
            except ldap.SERVER_DOWN as e:
                self._logger.warning(f"Host {connect_line}: {e}")

        else:
            raise TimeoutError(f"Can't contact LDAP servers")

        # Если область каталога не определена, производится запрос для установки области работы
        self.base = self.base if self.base else search_root_dse(connect=self._connect, _logger=self._logger)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Автоматическое закрытие сессии"""
        self._connect.unbind_s()
        return False

    def get_object(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
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

        if properties:
            if isinstance(properties, str):
                properties = [properties]

            if '*' in properties:
                if len(properties) != 1:
                    raise RuntimeError("При запросе всех атрибутов может быть только один знак *")
            else:
                properties = list(set([i.casefold() for i in properties]))
                properties += [i.casefold() for i in DataDSProperties[type_object.upper()].value
                               if i.casefold() not in properties]

        else:
            properties = list(set([i.casefold() for i in DataDSProperties[type_object.upper()].value]))

        if all([identity, ldap_filter]):
            raise RuntimeError("You can only use one search filter")
        elif identity:
            result = search_object(
                connect=self._connect,
                _logger=self._logger,
                ldap_filter=gen_filter_to_id(identity, type_object=type_object),
                search_base=self.base,
                search_scope=search_scope,
                properties=properties,
                type_object=type_object,
                only_one=True
            )
        elif ldap_filter:
            result = search_object(
                connect=self._connect,
                _logger=self._logger,
                ldap_filter=ldap_filter,
                search_base=self.base,
                search_scope=search_scope,
                properties=properties,
                type_object=type_object
            )
        else:
            raise RuntimeError("You must use one of the filters")

        return result

    def get_user(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
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
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="user")

    def get_group(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
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
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="group")

    def get_computer(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
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
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="computer")

    def get_contact(
            self, identity: str | dict | DSDict = None, ldap_filter: str = None,
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
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="contact")

    def get_group_member(self, identity: str | dict | DSDict) -> list[DSDict]:
        """
        Функция получения всех членов группы, с дополнительными атрибутами.

        Args:
            identity: Аргумент принимающий уникальные атрибуты группы для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).

        Returns:
            Список объектов из DS
        """

        if (isinstance(identity, DSDict) and identity.get('objectClass') == 'group' and identity.get(
                'distinguishedName')):
            pass
        else:
            identity = search_object(
                connect=self._connect,
                _logger=self._logger,
                ldap_filter=gen_filter_to_id(identity, type_object='group'),
                search_base=self.base,
                properties=None,
                type_object='group',
                only_one=True
            )[0]

        return search_object(
            connect=self._connect,
            _logger=self._logger,
            ldap_filter=f"(memberOf={identity['distinguishedName']})",
            search_base=self.base,
            properties=DataDSProperties['MEMBER'].value,
            type_object='member',
            only_one=False
        )

    def set_object(self, identity: str | dict | DSDict, remove: dict = None, add: dict[str, list] = None,
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

        special = DSDict({
            'displayName': display_name,
            'description': description
        })

        ds_set(connect=self._connect, type_object="object", identity=identity, base=self.base, dry_run=self.dry_run,
               remove=remove, add=add, replace=replace, clear=clear, special=special, _logger=self._logger)

    def set_user(self, identity: str | dict | DSDict, remove: dict = None, add: dict[str, list] = None,
                 replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                 description: str = None, sam_account_name: str = None, user_principal_name: str = None,
                 enabled: bool = None, password_never_expires: bool = None, account_not_delegated: bool = None,
                 change_password_at_logon: bool = None, account_expiration_date: bool | datetime | str = None) -> None:
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

        if user_principal_name and '@' not in user_principal_name:
            raise RuntimeError("В userprincipalname домен должен быть указан через @")

        special = DSDict()

        if display_name: special.update({'displayName': display_name})
        if description: special.update({'description': description})
        if sam_account_name: special.update({'sAMAccountName': sam_account_name})
        if user_principal_name: special.update({'userPrincipalName': user_principal_name})
        if account_expiration_date is not None: special.update({'accountExpires': account_expiration_date})
        if change_password_at_logon is not None: special.update({'pwdLastSet': change_password_at_logon})

        if [True for i in [enabled, password_never_expires, account_not_delegated] if i is not None]:
            special['userAccountControl'] = DSDict()

            if enabled is not None: special['userAccountControl']['Enabled'] = enabled
            if password_never_expires is not None:
                special['userAccountControl']['PasswordNeverExpires'] = password_never_expires
            if account_not_delegated is not None:
                special['userAccountControl']['AccountNotDelegated'] = account_not_delegated

        ds_set(connect=self._connect, type_object="user", identity=identity, base=self.base, dry_run=self.dry_run,
               remove=remove, add=add, replace=replace, clear=clear, special=special, _logger=self._logger)

    def set_group(self, identity: str | dict | DSDict, remove: dict = None, add: dict[str, list] = None,
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

        special = DSDict()

        if display_name: special.update({'displayName': display_name})
        if description: special.update({'description': description})
        if sam_account_name: special.update({'sAMAccountName': sam_account_name})

        if [True for i in [group_scope, group_category] if i is not None]:
            special['groupType'] = DSDict()

            if group_scope is not None: special['groupType']['GroupScope'] = group_scope
            if group_category is not None: special['groupType']['GroupCategory'] = group_category

        ds_set(connect=self._connect, type_object="group", identity=identity, base=self.base, dry_run=self.dry_run,
               remove=remove, add=add, replace=replace, clear=clear, special=special, _logger=self._logger)

    def set_computer(self, identity: str | dict | DSDict, remove: dict = None, add: dict[str, list] = None,
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

        special = DSDict({
            'displayName': display_name,
            'description': description,
        })

        ds_set(connect=self._connect, type_object="computer", identity=identity, base=self.base, dry_run=self.dry_run,
               remove=remove, add=add, replace=replace, clear=clear, special=special, _logger=self._logger)

    def set_contact(self, identity: str | dict | DSDict, remove: dict = None, add: dict[str, list] = None,
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

        special = DSDict({
            'displayName': display_name,
            'description': description,
        })

        ds_set(connect=self._connect, dry_run=self.dry_run, type_object="contact", identity=identity, base=self.base,
               remove=remove, add=add, replace=replace, clear=clear, special=special, _logger=self._logger)

    def set_account_password(self, identity: str | dict | DSDict, account_password: str) -> None:
        """
        Функция изменения пароля пользователя в DS. Принудительно снимает флаг "PASSWD_NOTREQD"

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            account_password: Новый пароль.
        """

        ds_set(connect=self._connect, type_object="user", identity=identity, base=self.base, dry_run=self.dry_run,
               replace={'unicodePwd': [account_password]},
               special=DSDict({'userAccountControl': DSDict({'PasswordNotRequired': False})}), _logger=self._logger)

    def set_account_unlock(self, identity: str | dict | DSDict) -> None:
        """
        Функция снятия временной блокировки пользователя в DS (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации.
        """

        ds_set(connect=self._connect, type_object="user", identity=identity, base=self.base, dry_run=self.dry_run,
               replace={'lockoutTime': ["0"]}, _logger=self._logger)

    def add_group_member(self, identity: str | dict | DSDict,
                         members: str | dict | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        """
        Функция добавления объектов в группу. Члены добавляются последовательно (один член, один запрос)

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            members: Аргумент принимающий уникальные атрибуты члена/членов группы (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
        """
        ds_set_member(connect=self._connect, _logger=self._logger, dry_run=self.dry_run,
                      identity=identity, base=self.base, members=members, action='add')

    def remove_group_member(self, identity: str | dict | DSDict,
                            members: str | dict | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        """
        Функция добавления объектов в группу. Члены удаляются последовательно (один член, один запрос)

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
            members: Аргумент принимающий уникальные атрибуты члена/членов группы (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict)).
        """
        ds_set_member(connect=self._connect, _logger=self._logger, dry_run=self.dry_run,
                      identity=identity, base=self.base, members=members, action='remove')

    def move_object(self, identity: str | dict | DSDict, target_path: str) -> None:
        """
        Функция перемещения объектов между Организационными юнитами (изменяется distinguishedName).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
            target_path: Аргумент принимающий distinguishedName нового Организационного юнита
        """
        result = search_object(
            connect=self._connect,
            _logger=self._logger,
            ldap_filter=gen_filter_to_id(identity, type_object='object'),
            search_base=self.base,
            properties=['cn', 'distinguishedName'],
            type_object='object',
            only_one=True,
        )[0]

        self._logger.info(f"Move object: DN: {result['distinguishedName']}, new path: {target_path}")

        if not self.dry_run:
            self._connect.rename_s(result['distinguishedName'],
                                   ldap.dn.explode_dn(result['distinguishedName'])[0], target_path)
        else:
            self._logger.warning("Enabled dry run")

    def rename_object(self, identity: str | dict | DSDict, new_name: str) -> None:
        """
        Функция переименования объекта (изменяются атрибуты cn, name и distinguishedName).

        Args:
            identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
            new_name: Аргумент принимающий новое имя
        """
        result = search_object(
            connect=self._connect,
            _logger=self._logger,
            ldap_filter=gen_filter_to_id(identity, type_object='object'),
            search_base=self.base,
            properties=['cn', 'name', 'distinguishedName'],
            type_object='object',
            only_one=True,
        )[0]

        self._logger.info(f"Rename object: DN: {result['distinguishedName']}, new name: {new_name}, "
                          f"old name: {result['name']}, "
                          f"old cn: {result['cn']}")

        if not self.dry_run:
            self._connect.rename_s(result['distinguishedName'], f"CN={new_name}")
        else:
            self._logger.warning("Enabled dry run")

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
        dict_object = DSDict()

        dict_object['userAccountControl'] = [str(gen_uac(
            uac=UAC_FLAGS['NORMAL_ACCOUNT'],
            enabled=enabled,
            password_never_expires=password_never_expires,
            account_not_delegated=account_not_delegated,
            password_not_required=False,
        ))]

        if change_password_at_logon is not None:
            dict_object['pwdLastSet'] = [gen_change_pwd_at_logon(change_password_at_logon)]

        if account_expiration_date is not None:
            dict_object['accountExpires'] = [gen_account_exp_date(account_expiration_date)]

        if user_principal_name:
            dict_object['userPrincipalName'] = [user_principal_name]

        dict_object['unicodePwd'] = [account_password]

        dict_object['sAMAccountName'] = [sam_account_name]

        ds_new(connect=self._connect, dry_run=self.dry_run, type_object='user', path=path, name=name,
               display_name=display_name, extend=dict_object, other_attributes=other_attributes, _logger=self._logger)

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

        dict_object = DSDict()

        dict_object['sAMAccountName'] = [sam_account_name]
        dict_object['groupType'] = [str(gen_gt(gt=0, group_scope=group_scope, group_category=group_category))]

        ds_new(connect=self._connect, dry_run=self.dry_run, type_object='group', path=path, name=name,
               display_name=display_name, extend=dict_object, other_attributes=other_attributes, _logger=self._logger)

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
        ds_new(connect=self._connect, dry_run=self.dry_run, type_object='contact', path=path, name=name,
               display_name=display_name, extend=None, other_attributes=other_attributes, _logger=self._logger)

    def remove_object(self, identity: str | dict | DSDict, type_object: DS_TYPE_OBJECT = "object") -> None:
        """
            Функция удаления объекта.

            Args:
                identity: Аргумент принимающий уникальные атрибуты пользователя для идентификации (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict)).
                type_object: К фильтру поиска добавляется фильтр типа объекта ("object", "user", "group", "computer" или "contact")
        """

        result = search_object(
            connect=self._connect,
            _logger=self._logger,
            ldap_filter=gen_filter_to_id(identity, type_object=type_object),
            search_base=self.base,
            properties=['distinguishedName'],
            type_object=type_object,
            only_one=True,
        )[0]

        self._logger.info(f"Remove object: DN: {result['distinguishedName']}")

        if not self.dry_run:
            self._connect.delete_s(result['distinguishedName'])
        else:
            self._logger.warning("Enabled dry run")

    def remove_user(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа пользователь.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """
        self.remove_object(identity=identity, type_object="user")

    def remove_group(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """
        self.remove_object(identity=identity, type_object="group")

    def remove_computer(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid, sAMAccountName или словарь объекта DS (DSDict))
        """
        self.remove_object(identity=identity, type_object="computer")

    def remove_contact(self, identity: str | dict | DSDict) -> None:
        """
            Функция удаления объекта типа группа.

            Args:
                identity: Аргумент для поиска только одного объекта в каталоге (distinguishedName, objectGUID, objectSid или словарь объекта DS (DSDict))
        """
        self.remove_object(identity=identity, type_object="contact")
