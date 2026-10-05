"""
Функция для формирования base-строки. Основное применение, если в строке не найдены
"""
import logging

import ldap
from .data import Event
from .func_ds_get import object_processing


def search_root_dse(connect, _logger: logging.LoggerAdapter) -> dict:
    result = get_root_dse(connect, _logger, "(objectClass=*)", ["namingContexts"])

    # Возвращение первого элемента из списка областей, с учётом фильтров
    return [nc for nc in result[0]["namingContexts"]
            if nc.lower().startswith("dc=")
            and 'DomainDnsZones'.lower() not in nc.lower()
            and 'ForestDnsZones'.lower() not in nc.lower()][0]


def get_root_dse(connect, _logger: logging.LoggerAdapter, ldap_filter: str,
                 properties: str | tuple[str] | list[str]) -> list:
    base = ""
    search_scope = ldap.SCOPE_BASE
    properties = [properties] if isinstance(properties, str) else properties

    _logger.debug({'msg': 'Get domain DN', 'search_base': base, 'search_scope': search_scope,
                   'ldap_filter': ldap_filter, 'properties': properties},
                  extra={'e_id': Event.QUERY_GET_ROOTDSE})

    # Получения списка корневых областей
    res = connect.search_s(base, search_scope, ldap_filter, properties)
    return [object_processing(connect=connect, _logger=_logger, data=i[1], properties=properties,
                              properties_shadow=[], range_on=True) for i in res]
