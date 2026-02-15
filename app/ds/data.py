import typing
from enum import Enum

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
