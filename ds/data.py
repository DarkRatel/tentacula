from enum import Enum


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
            "Surname", "UserPrincipalName", "Enabled"]
    GROUP = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID", "sAMAccountName", "objectSid", "GroupScope",
             "GroupCategory"]
    COMPUTER = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID", "DNSHostName", "Enabled", "sAMAccountName",
                "objectSid", "UserPrincipalName", "userAccountControl"]
    CONTACT = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID"]
    MEMBER = ["distinguishedName", "Name", "ObjectClass", "ObjectGUID", "sAMAccountName", "objectSid"]
