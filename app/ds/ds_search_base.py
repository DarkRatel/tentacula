"""
Функция для формирования base-строки. Основное применение, если в строке не найдены
"""
import ldap


def search_root_dse(connect, _logger) -> str:
    """
    Функция формирования base-строки подключения

    Args:
        connect: Переменная с открытой сессией к СК
        _logger: Переменная с логированием
    """
    base = ""
    search_scope = ldap.SCOPE_BASE
    ldap_filter = "(objectClass=*)"
    properties = ["namingContexts"]

    _logger.debug(f"Get dn: search_base: {base}, search_scope: {search_scope}, "
                  f"ldap_filter: {ldap_filter}, properties: {properties}")

    # Получения списка корневых областей
    res = connect.search_s(base, search_scope, ldap_filter, properties)
    naming_contexts = [nc.decode() for nc in res[0][1]["namingContexts"]]

    # Возвращение первого элемента из списка областей, с учётом фильтров
    return [nc for nc in naming_contexts
            if nc.lower().startswith("dc=")
            and 'DomainDnsZones'.lower() not in nc.lower()
            and 'ForestDnsZones'.lower() not in nc.lower()][0]
