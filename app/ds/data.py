"""
Константы со стачными значениями
"""
import typing
from enum import Enum

# Набор переменных для проверки корректности получаемых значений в ключах
DS_TYPE_SCOPE = typing.Literal["base", "onelevel", "subtree"]
DS_TYPE_OBJECT = typing.Literal["object", "user", "group", "computer", "contact"]
DS_TYPE_OBJECT_SYSTEM = typing.Literal["object", "user", "group", "computer", "contact", "member"]
DS_GROUP_SCOPE = typing.Literal["DomainLocal", "Global", "Universal"]
DS_GROUP_CATEGORY = typing.Literal["Security", "Distribution"]
DS_ACTION_MEMBER = typing.Literal["add", "remove"]


class DataDSLDAP(Enum):
    """
    LDAP-фильтры типов объектов. Функция <unit> используется для объединения исходного LDAP-запроса с типом объекта
    (вызывается после вызова переменной)
    """
    OBJECT = ""
    USER = "(&(objectCategory=person)(objectClass=user))"
    GROUP = "(objectCategory=group)"
    COMPUTER = "(objectCategory=computer)"
    CONTACT = "(objectClass=contact)"
    MEMBER = ("(|(&(objectCategory=person)(objectClass=user))(objectCategory=group)"
              "(objectCategory=computer)(objectClass=contact))")

    def unit(self, data: str):
        """
        Функция добавляющая фильтр объекта в переданный фильтр.
        Пример вызова: DataDSLDAP[<название объекта из класса>].unit(<исходный фильтр>>)
        :param data: Исходный фильтр
        :return: Обновлённый LDAP-фильтр
        """
        return f"(&{self.value}{data})"


class DataDSProperties(Enum):
    """
    Список свойств, которые запрашиваются по умолчанию
    """
    OBJECT = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID"]
    USER = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID", "GivenName", "sAMAccountName", "objectSid",
            "sn", "UserPrincipalName", "Enabled"]
    GROUP = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID", "sAMAccountName", "objectSid", "GroupScope",
             "GroupCategory"]
    COMPUTER = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID", "DNSHostName", "Enabled", "sAMAccountName",
                "objectSid", "UserPrincipalName", "userAccountControl"]
    CONTACT = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID"]
    MEMBER = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID", "sAMAccountName", "objectSid"]

from dataclasses import dataclass


@dataclass
class Event:
    """События для логов"""
    AUTH_SUCCESS = 'ds.auth.success'
    AUTH_FAILED_CREDENTIAL = 'ds.auth.failed_credential'
    AUTH_HOST_UNAVAILABLE = 'ds.auth.host_unavailable'
    AUTH_ERROR = 'ds.auth.error'
    AUTH_ACCESS_DENIED = 'ds.auth.access_denied'
    AUTH_LOGGED_OUT = "ds.auth.logged_out"

    QUERY_GET_ROOTDSE = 'ds.query.get.root_dse' # get_root_dse
    QUERY_GET_OBJECT = 'ds.query.get.object'  # get_object
    QUERY_GET_USER = 'ds.query.get.user'  # get_user
    QUERY_GET_GROUP = 'ds.query.get.group'  # get_group
    QUERY_GET_COMPUTER = 'ds.query.get.computer'  # get_computer
    QUERY_GET_CONTACT = 'ds.query.get.contact'  # get_contact
    QUERY_GET_RANGE = 'ds.query.get.range'
    QUERY_GET_MEMBER = 'ds.query.get.member.group'  # get_group_member

    QUERY_SET_OBJECT = 'ds.query.set.object'  # set_object
    QUERY_SET_USER = 'ds.query.set.user'  # set_user
    QUERY_SET_GROUP = 'ds.query.set.group'  # set_group
    QUERY_SET_COMPUTER = 'ds.query.set.computer'  # set_computer
    QUERY_SET_CONTACT = 'ds.query.set.contact'  # set_contact

    QUERY_SET_PASSWORD = 'ds.query.set.account.password'  # set_account_password
    QUERY_SET_UNLOCK = 'ds.query.set.account.unlock'  # set_account_unlock

    QUERY_ADD_MEMBER = 'ds.query.set.member.add'  # add_group_member
    QUERY_REMOVE_MEMBER = 'ds.query.set.member.remove'  # remove_group_member

    QUERY_MOVE_OBJECT = 'ds.query.move.object'  # move_object
    QUERY_RENAME_OBJECT = 'ds.query.rename.object'  # rename_object

    QUERY_NEW_OBJECT = 'ds.query.new.user'  # new_user
    QUERY_NEW_GROUP = 'ds.query.new.group'  # new_group
    QUERY_NEW_CONTACT = 'ds.query.new.contact'  # new_contact

    QUERY_REMOVE_OBJECT = 'ds.query.remove.object'  # remove_object,
    QUERY_REMOVE_USER = 'ds.query.remove.user' # remove_user
    QUERY_REMOVE_GROUP = 'ds.query.remove.group' # remove_group
    QUERY_REMOVE_COMPUTER = 'ds.query.remove.computer' # remove_computer
    QUERY_REMOVE_CONTACT = 'ds.query.remove.contact' # remove_contact
    UNWILLING_TO_PERFORM = 'ds.unwilling_to_perform'
    DEBUG = 'ds.debug'
    DRY_RUN = 'ds.dry_run'