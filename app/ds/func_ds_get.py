"""
Функции чтения данных из СК
"""
import struct
import uuid
import re
from datetime import datetime, timedelta

import ldap
import ldap.filter
from ldap.controls.libldap import SimplePagedResultsControl

from .data import DataDSLDAP, DS_TYPE_SCOPE, DS_TYPE_OBJECT_SYSTEM
from .ds_dict import DSDict
from .attributes_type import ATTR_TYPES
from .convertors_value import convert_grouptype, convert_object_class, uac_to_flags, _UAC_FLAGS

# Особая обработка атрибутов, которая противоречит стандартному правилу чтения атрибута указанного в TYPE_HANDLERS
ATTR_SPECIAL = DSDict({
    "objectGUID": lambda v: [str(uuid.UUID(bytes_le=i)) for i in v],
    "objectClass": lambda v: convert_object_class(flags=[i.decode("utf-8") for i in v]),
    "rIDAvailablePool": lambda v: [i.decode("utf-8") for i in v],
})

# Правила обработки атрибутов в зависимости от того указанного в ATTR_TYPES
TYPE_HANDLERS = {
    # Строка Distinguished ж\Name
    "2.5.5.1": lambda v: [i.decode("utf-8") for i in v],
    # Строка без учета регистра символов (CaseIgnore)
    "2.5.5.4": lambda v: [i.decode("utf-8") for i in v],
    # Булев
    "2.5.5.8": lambda v: [c_bool_string_to_bool(i.decode("utf-8")) for i in v],
    # Целое число
    "2.5.5.9": lambda v: [int(i) for i in v],
    # Время в формате UTC (напр. 20240916132547.0Z).
    "2.5.5.11": lambda v: [c_datetime_unicode_to_python(i) for i in v],
    # Юникод (Строка "Пропустить регистр")
    "2.5.5.12": lambda v: [i.decode("utf-8") for i in v],
    # Большое целое число (IADsLargeInteger) (целое 64-битное, например pwdLastSet, lastLogonTimestamp).
    "2.5.5.16": lambda v: [c_datetime_win_to_python(i) for i in v],
    # Идентификатор безопасности (Октетная строка)
    "2.5.5.17": lambda v: [c_sid_byte_to_string(i) for i in v]
}

# Создание новых атрибутов на базовых атрибутов (все специальные атрибуты начинаются с заглавной буквы
# Первый ключ это название исходного атрибута,
# значение это возможные специальные атрибуты, которые могут быть созданы из исходного
ATTR_EXTEND = {
    "userAccountControl": {
        'Enabled': lambda v: False if _UAC_FLAGS["ACCOUNTDISABLE"] & v else True,
        'PasswordNeverExpires': lambda v: True if _UAC_FLAGS["DONT_EXPIRE_PASSWORD"] & v else False,
        'AccountNotDelegated': lambda v: True if _UAC_FLAGS["NOT_DELEGATED"] & v else False,
        'PasswordNotRequired': lambda v: True if _UAC_FLAGS["PASSWD_NOTREQD"] & v else False,
        'FlagsUAC': lambda v: uac_to_flags(v),
    },
    "groupType": {
        'GroupScope': lambda v: return_groupscope(convert_grouptype(v, skip_error=True)),
        'GroupCategory':
            lambda v: "Security" if "SECURITY_ENABLED" in convert_grouptype(v, skip_error=True) else "Distribution",
        'FlagsGT': lambda v: convert_grouptype(v, skip_error=True),
    },
    "pwdLastSet": {
        'ChangePasswordAtLogon': lambda v: True if v == 0 else False,
    },
}


def object_processing(connect, _logger, data, properties, properties_shadow) -> DSDict:
    """Основная функция конвертации данных полученных объекта полученных из СК"""
    result = DSDict()
    # Перебор полученных атрибутов и значений
    for attr, values in data.items():
        # Если есть атрибут со свойством "range", атрибут перезапрашивается, пока не будут получены все значения
        if ';' in attr:
            temp = attr.split(';')[0]
            temp, attr = attr, temp
            values += search_attribute_range(
                connect=connect, dn=data['distinguishedName'][0].decode("utf-8"), attribute=temp, _logger=_logger
            )

        # Получение базовых свойств атрибута. Если их нет в библиотеке, атрибут считается мультистроковым
        action = ATTR_TYPES.get(attr, ('unknown', False))

        # Получение правила обработки атрибута.
        # Последовательность:
        # Либо правило для конкретного атрибута
        # Либо правило для специальной обработки атрибута
        # Либо значение преобразовывается в hex, для совместимости с JSON
        handler = ATTR_SPECIAL.get(attr, TYPE_HANDLERS.get(action[0], lambda v: [f"hex:{i.hex()}" for i in v]))

        # Исполнение конвертации значения согласно полученному правилу
        result[attr] = handler(values)

        # Если атрибут должен содержать одно значение, остаётся только первый элемент
        result[attr] = result[attr][0] if action[1] else result[attr]

    # Обработка вычисляемых атрибутов
    for attr, rules in ATTR_EXTEND.items():
        if attr in result:
            for attr_extend, handler_extend in rules.items():
                # Особый атрибут создаётся, если он был запрошен или если были запрошены все атрибуты
                if attr_extend.lower() in properties or '*' in properties:
                    result[attr_extend] = handler_extend(result[attr])

    # Удаление всех атрибутов, которые должны были быть скрыты
    [result.pop(attr) for attr in properties_shadow if attr in result]

    return result


# Регулярное выражение для поиска атрибута и оператора
ESCAPE_START_FILTER = re.compile("!?[A-Za-z0-9]*[0-9.:]*?[><~]?=")
# Регулярное выражение для разбивки минимального элемента ldap-фильтра на части:
# открывающая скобка, атрибут, оператор, значение, закрывающая скобка
BREAK_INTO_PIECES = re.compile(r"^(\()(!?[A-Za-z0-9]*[0-9.:]*?)([><~]?=)(.*)(\)$)")
# Регулярное выражение для проверки была ли уже конвертирован ldap-фильтр в RFC4515
RFC4515_ESCAPE_RE = re.compile(r"\\[0-9A-F-a-f]{2}")


def isolation_filter(ldap_filter: str) -> str:
    """
    Конвертация ldap-фильтра в RFC4515

    Args:
        ldap_filter: строка ldap-фильтра
    """

    # Если исходная строка уже имеет символы похожие на формат RFC4515, обработка не производится
    if bool(RFC4515_ESCAPE_RE.search(ldap_filter)):
        return ldap_filter

    elements = {}  # Словарь для найденных минимальных элементов ldap-фильтра.
    # Словарь уникальный id (<*>) элемента, значение элемент
    element_id = 0  # Счётчик элементов для создания id

    def decomposition(text: str) -> str:
        """
        Функция выделения минимального элемента фильтра.
        Если элемент найден, то он выписывается в массив и процесс повторяется.
        Если минимальный элемент больше не найден, то функция завершается

        Args:
            text: строка ldap-фильтра или её обрабатываемая версия
        """

        # Использование глобальных переменных, чтобы выписывать результаты вне функции
        nonlocal elements
        nonlocal element_id

        # Поиск начала первого минимального элемента
        ko = ESCAPE_START_FILTER.search(text)

        # Если элемент найден, и перед элементом стояла открывающая скобка, значит обработка начинается
        if ko and text[ko.start() - 1] == '(':

            open_bracket = 0 # Переменная для счёта открывающих скобок
            close_bracket = 0 # Переменная для счёта закрывающих скобок

            # Сразу после найденного начала элементы, идёт перебор каждого последующего знака, для поиска конца значения
            for ne in range(ko.end() + 1, len(text)):
                # Если найдена закрывающая скобка, происходит основная обработка
                if text[ne] == ')':
                    # Если счётчик открывающих и закрывающих скобок равны или следующий элемент открывающая скобка,
                    # значит последний элемент в строке найден
                    if open_bracket == close_bracket or text[ne + 1] == '(':
                        element_id += 1
                        idx = f'<{element_id}>'
                        elements.update({idx: text[ko.start() - 1:ne + 1]})
                        # Из строки заменяется найденный элемент на id и строка передаётся на повторную обработку
                        return decomposition(text[:ko.start() - 1] + idx + text[ne + 1:])
                    # Иначе счётчик закрывающихся скобок увеличивается
                    close_bracket += 1
                # Если встречается открывающая скобка, то счётчик увеличивается и обработка продолжается
                elif text[ne] == '(':
                    open_bracket += 1
            # Если конец значения не найден, фиксируется ошибка
            raise RuntimeError("Ошибка парсинга ldap-фильтра - не был найден конец значения")

        else:
            return text

    # Обработка ldap-фильтра
    skeleton = decomposition(ldap_filter)

    # Если в ldap-фильтре, в котором остались только id минимальных элементов
    # не одинаковое количество открытых и закрытых скобок, значит обработка фильтра прошла некорректно
    if skeleton.count('(') != skeleton.count(')'):
        raise ValueError('Не удалось обработать фильтр из-за скобок. Попробуйте изолировать круглые скобки в значениях')

    # Обработка минимальных найденных элементов ldap-фильтра
    for k, v in elements.items():
        # Разбивка элемента на части
        v = BREAK_INTO_PIECES.split(v)

        # Для корректного поиска, требуется конвертация в бинарник, поэтому есть исключение
        if v[2].lower() == 'objectguid':
            v[4] = c_guid_to_binary(v[4])
        else:
            # Изоляция значения
            v[4] = ldap.filter.escape_filter_chars(v[4])
            # Если в значении есть знак *, он будет восстановлен после изоляции символов
            v[4] = v[4].replace(r"\2a", "*")

        # Обработанный минимальный элемент возвращается на свой место
        skeleton = skeleton.replace(k, ''.join(v))

    return skeleton


def search_object(connect, _logger, ldap_filter, search_base, properties, type_object: DS_TYPE_OBJECT_SYSTEM = 'object',
                  search_scope: DS_TYPE_SCOPE = "subtree", only_one: bool = False,
                  result_set_size: int | None = None) -> list[DSDict]:
    """
    Функция поиска объектов в СК

    Args:
        connect: Переменная с открытым подключением к СК
        _logger: Переменная с логгером
        ldap_filter: исходный LDAP-фильтр СК
        search_base: Область поиска в дереве СК
        properties: Список запрошенных атрибутов (* может быть запрошена только отдельно)
        type_object: Искомый тип объекта (по умолчанию object)
        search_scope: Глубина поиска
        only_one: Указатель, что поиск обязательно должен вернуть только один объект иначе ошибка
        result_set_size: Ограничение на число объектов, которые должно быть возвращено
    """
    _logger.debug(f"SOURCE ldap_filter: {ldap_filter}")

    # Конвертация LDAP-фильтра в вариант пригодный для LDAP
    ldap_filter = isolation_filter(ldap_filter)

    # Добавление в LDAP-фильтр дополнительных правил фильтрации, в зависимости от type_object
    ldap_filter = DataDSLDAP[type_object.upper()].unit(ldap_filter)

    if only_one and '*' in ldap_filter:
        raise RuntimeError(f"При точеном поиске недопустим параметр разрешающий нестрогий поиск (*): {ldap_filter}")

    # Далее формируется список запрошенных атрибутов и атрибутов,
    # которые должны быть скрыты, если они нужны для создания особых атрибутов, но не были запрошены
    if not properties:
        properties = []

    properties_low = [i.lower() for i in properties]
    properties_shadow = []

    if '*' not in properties:
        # Обязательно добавляются атрибуты distinguishedName и objectClass,
        # так как они требуются для корректной обработки объекта
        if 'distinguishedName'.lower() not in properties_low:
            properties += ['distinguishedName']
        if 'objectClass'.lower() not in properties_low:
            properties += ['objectClass']

        for attr, attr_ext in ATTR_EXTEND.items():
            # Если дополнительный атрибут уже добавлен в скрытые, то пропускается его обработка
            if attr.lower() in properties_low:
                continue

            # Перебор особых атрибутов. Если особый атрибут есть,
            # то исходный атрибут добавляется и обработка завершается
            for name_ext, _ in attr_ext.items():
                if name_ext.lower() in properties_low:
                    properties_shadow += [attr.lower()]
                    properties += [attr.lower()]
                    break

    # Определение грубины поиска, на основе текстового указателя
    if search_scope == "subtree":
        search_scope = ldap.SCOPE_SUBTREE
    elif search_scope == "onelevel":
        search_scope = ldap.SCOPE_ONELEVEL
    elif search_scope == "base":
        search_scope = ldap.SCOPE_BASE
    else:
        raise RuntimeError(f"Неизвестный тип области поиска: {search_scope}")

    _logger.info(f"Get {type_object}: search_base: {search_base}, search_scope: {search_scope}, "
                 f"ldap_filter: {ldap_filter}, properties: {properties}")

    # Размер очереди по умолчанию
    req_ctrl = SimplePagedResultsControl(criticality=False, size=1499, cookie='')

    # Цикл на получение всех объект
    total_results = []
    while True:
        # Запрос на получение результатов
        msgid = connect.search_ext(base=search_base, scope=search_scope, filterstr=ldap_filter, attrlist=properties,
                                   serverctrls=[req_ctrl])

        # Вычленение результатов
        _, objects, _, server_sprc = connect.result3(msgid)

        # Поиск response control с cookie
        pctrls = [c for c in server_sprc if c.controlType == SimplePagedResultsControl.controlType]

        # Обработка найденных объектов
        for one_object in objects:
            if one_object[0]:
                # Если указан лимит на объекты, будет прерывание, если лимит уже исчерпан
                if result_set_size and len(total_results) >= result_set_size:
                    break

                # Обработка и сохранение объекта
                total_results.append(object_processing(connect=connect, data=one_object[1], properties=properties,
                                                       properties_shadow=properties_shadow, _logger=_logger))

        # Если cookie есть
        if pctrls:
            # Если лимит уже использован и cookie остался, отправляется запрос прерывания очереди
            if result_set_size and len(total_results) >= result_set_size and pctrls[0].cookie:
                # Корректно закрываем paged search sequence на сервере
                abandon_ctrl = SimplePagedResultsControl(criticality=True, size=0, cookie=pctrls[0].cookie)

                connect.search_ext(base=search_base, scope=search_scope, filterstr=ldap_filter, attrlist=properties,
                                   serverctrls=[abandon_ctrl], sizelimit=0)
                break

            if pctrls[0].cookie:
                # Копирование cookie из элемента управления ответом в элемент управления запросом
                req_ctrl.cookie = pctrls[0].cookie
            else:
                break
        else:
            break

    # Вызвать исключение, если ожидается один объект, но результат не соответствует
    if only_one:
        if len(total_results) == 0:
            raise RuntimeError("Объект не найден")
        if len(total_results) > 1:
            raise RuntimeError("Найдено больше одного объекта")

    return total_results


def search_attribute_range(connect, _logger, dn: str, attribute: str) -> list:
    """
    Функция получения всех оставшихся значений из переменной состоящей из страниц

    Args:
        connect: Переменная с открытой сессией к СК
        _logger: Переменная с логированием
        dn: distinguishedName объекта
        attribute: Название атрибута, для которого необходимо запросит оставшиеся значения из атрибута
    """
    all_range = []

    attr_name = attribute.split(";")[0]
    step = 1499  # Размер шага (шаг не может превышать размер правил DS)
    start = int(attribute.split(';range=')[1].split('-')[1]) + 1  # От кого числа в массиве начинается
    end = start + step  # До кого числа возвращаться

    search_base = ldap.SCOPE_SUBTREE
    ldap_filter = "(objectClass=*)"

    while True:
        attribute = f"{attr_name};range={start}-{end}"

        _logger.debug(f"Get range: search_base: {search_base}, search_scope: {dn}, "
                      f"ldap_filter: {ldap_filter}, properties: {[attribute]}")

        res = connect.search_s(dn, search_base, ldap_filter, [attribute])[0][1]

        am = [i for i in res.keys() if f'{attr_name};range=' in i][0]

        if res[am]:
            all_range += res[am]
        else:
            break

        start, end = am.split(';range=')[1].split('-')

        if '*' in end:
            break
        else:
            start = int(end) + 1
            end = int(end) + step + 1

    return all_range


def gen_filter_to_id(identity: str | DSDict | dict, type_object: DS_TYPE_OBJECT_SYSTEM = "object",
                     return_dict: bool = False) -> str | DSDict:
    """
    Конвертирование полученного идентификатора в словарь с подходящими атрибутами или формирование строки LDAP-поиска
    по самому подходящему атрибуту.
    Приоритет атрибутов:
        1. sAMAccountName для "user", "computer", "group", "member";
        2. distinguishedName;
        3. ObjectGUID;
        4. objectSid.

    Args:
        identity:
        type_object:
        return_dict:
    """
    # Если передан словарь, то ожидается, что в нём передан словарь объекта из СК
    if isinstance(identity, dict):
        identity = DSDict(identity)
    # Если передана строка, то она анализируется и конвертируется в подходящий словарь
    elif isinstance(identity, str):
        if re.search(r'^cn=|^ou=|^dc=', identity.lower()):
            identity = DSDict({"distinguishedName": identity})
        # Если передан GUID, формируется LDAP-фильтр для поиска объекта
        elif re.search(r'^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$', identity.lower()):
            identity = DSDict({"objectGUID": identity})
        # Если передан SID, формируется LDAP-фильтр для поиска объекта
        elif "s-1-5" in identity.lower() and type_object in ["user", "computer", "group", "member"]:
            identity = DSDict({"objectSid": identity})
        # Если передан текст, то будет совершена попытка искать этот текст в атрибуте sAMAccountName
        elif type_object in ["user", "computer", "group", "member"]:
            identity = DSDict({"sAMAccountName": identity})
        else:
            raise RuntimeError(f"Ошибка определения способа поиска объекта в службе каталогов для значения: {identity}")

    # Если требуется вернуть только словарь пользователя, он возвращается
    if return_dict:
        return identity

    # Создание наиболее подходящего LDAP-фильтра
    if 'sAMAccountName' in identity and type_object in ["user", "computer", "group", "member"]:
        search_line = f"(sAMAccountName={identity['sAMAccountName']})"
    elif 'distinguishedName' in identity:
        search_line = f"(distinguishedName={identity['distinguishedName']})"
    elif 'ObjectGUID' in identity:
        search_line = f"(ObjectGUID={identity['ObjectGUID']})"
    elif 'objectSid' in identity:
        search_line = f"(objectSid={identity['objectSid']})"
    else:
        raise RuntimeError("В объекте нет подходящих атрибутов")

    return search_line


def c_sid_byte_to_string(data: bytes) -> str:
    """Конвертирование objectSid из байта в строку"""
    version = struct.unpack('B', data[0:1])[0]
    assert version == 1, version
    length = struct.unpack('B', data[1:2])[0]
    authority = struct.unpack(b'>Q', b'\x00\x00' + data[2:8])[0]
    string = 'S-%d-%d' % (version, authority)
    data = data[8:]
    assert len(data) == 4 * length
    for i in range(length):
        value = struct.unpack('<L', data[4 * i:4 * (i + 1)])[0]
        string += '-%d' % value

    return string


def c_datetime_unicode_to_python(data: bytes) -> datetime:
    """Конвертование даты формата Unicode в datetime"""
    return datetime.strptime(data.decode("utf-8"), "%Y%m%d%H%M%S.0Z")


def c_datetime_win_to_python(data: bytes) -> datetime | int:
    """Конвертирование даты формата Windows в datetime. Если переданы числа исключения, то они возвращаются как int"""
    if data in [b'0', b'9223372036850000000', b'9223372036854775807', b'-9223372036854775808']:
        return int(data.decode("utf-8"))

    return (datetime(1601, 1, 1, tzinfo=datetime.now().astimezone().tzinfo) +
            timedelta(seconds=int(data) / 10_000_000))


def return_groupscope(flags) -> str:
    """Конвертирование базового обозначения типа УЗ в классический AD"""
    if 'ACCOUNT_GROUP' in flags:
        return "Global"
    elif 'RESOURCE_GROUP' in flags:
        return "DomainLocal"
    elif 'UNIVERSAL_GROUP' in flags:
        return "Universal"
    raise RuntimeError("Error Search Flag Group")


def c_bool_string_to_bool(data: str) -> bool | None:
    """Конвертование BOOL полученного как текст в данные типа bool"""
    if data == 'TRUE':
        return True
    elif data == 'FALSE':
        return False
    elif data is None:
        return None
    raise RuntimeError(f"Ошибка определения болевого значения: {data}")


def c_guid_to_binary(data: str) -> str:
    """
    Конвертация GUID в байты
    :param data: обработанный GUID (XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)
    :return: байтовая последовательность GUID'а
    """
    guid_replace = data.replace("-", "")
    new_order = [6, 7, 4, 5, 2, 3, 0, 1, 10, 11, 8, 9, 14, 15, 12, 13]  # the weird-ordered stuff
    for i in range(16, len(guid_replace)):
        new_order.append(i)  # slam the rest on
    guid_string_in_search_order = str.join('', [guid_replace[i] for i in new_order])
    identity_convert = ''.join(['\\%s' % str.join('', guid_string_in_search_order[i:i + 2]) for i in
                                range(0, len(guid_string_in_search_order), 2)])
    return identity_convert
