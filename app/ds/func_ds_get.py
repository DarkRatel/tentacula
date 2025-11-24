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
from .convertors_value import convert_grouptype, convert_object_class, UAC_FLAGS
from .ds_function import search_attribute_range

TYPE_HANDLERS = {
    # Distinguished Name (DN, ссылка на другой объект AD).
    "2.5.5.1": lambda v: v.decode("utf-8"),
    # OID String (строка с OID, например schemaIDGUID).
    "2.5.5.2": lambda v: v.decode("utf-8"),
    # Case-Insensitive String (обычный текст, не чувствительный к регистру).
    "2.5.5.4": lambda v: v,
    # Case-Sensitive String (текст, где регистр важен).
    "2.5.5.5": lambda v: v.decode("utf-8"),
    # Object Identifier (OID) (внутренний идентификатор схемы).
    "2.5.5.6": lambda v: int(v),
    # Numeric String (строка, содержащая только цифры).
    "2.5.5.7": lambda v: v,
    # Boolean
    "2.5.5.8": lambda v: c_bool_string_to_bool(v),
    # Printable String (строка, ограниченный набор символов ASCII).
    "2.5.5.9": lambda v: int(v.decode("utf-8")),
    # Integer (32-битное число).
    "2.5.5.10": lambda v: str(uuid.UUID(bytes_le=v)),
    # Generalized Time (дата/время в формате LDAP, напр. 20240916132547.0Z).
    "2.5.5.11": lambda v: c_datetime_unicode_to_python(v),
    # DN with String (Distinguished Name + строка, например member).
    "2.5.5.12": lambda v: v.decode("utf-8"),
    # Presentation Address (старый тип для X.500, редко используется).
    "2.5.5.13": lambda v: v,
    # DN with Binary (DN + бинарные данные, например memberOfBL).
    "2.5.5.14": lambda v: v,
    # Unicode String (основной текстовый тип в AD).
    "2.5.5.15": lambda v: v,
    # LargeInteger (целое 64-битное, часто хранится как high/low — например pwdLastSet, lastLogonTimestamp).
    "2.5.5.16": lambda v: c_datetime_win_to_python(v),
    # SID (Security Identifier).
    "2.5.5.17": lambda v: c_sid_byte_to_string(v),
    # Если неизвестный атрибут
    "unknown": lambda v: v,
}

ATTR_EXTEND = DSDict({
    "objectClass": [
        ('objectClass', lambda v: convert_object_class(flags=v))
    ],
    "userAccountControl": [
        ('Enabled', lambda v: False if UAC_FLAGS["ACCOUNTDISABLE"] & v else True),
        ('PasswordNeverExpires', lambda v: True if UAC_FLAGS["DONT_EXPIRE_PASSWORD"] & v else False),
        ('AccountNotDelegated', lambda v: True if UAC_FLAGS["NOT_DELEGATED"] & v else False),
        ('PasswordNotRequired', lambda v: True if UAC_FLAGS["PASSWD_NOTREQD"] & v else False),
    ],
    "groupType": [
        ('GroupScope', lambda v: return_groupscope(convert_grouptype(v))),
        ('GroupCategory', lambda v: "Security" if "SECURITY_ENABLED" in convert_grouptype(v) else "Distribution")
    ],
    "pwdLastSet": [
        ('ChangePasswordAtLogon', lambda v: True if v == 0 else False),
    ],
})


def object_processing(connect, data, properties, properties_shadow):
    """Основная функция конвертации данных полученных об объекте СК"""
    result = DSDict()
    for attr, values in data.items():
        if ';' in attr:
            temp = attr.split(';')[0]
            temp, attr = attr, temp
            values += search_attribute_range(connect=connect, dn=data['distinguishedName'][0].decode("utf-8"),
                                             attribute=temp)

        action = ATTR_TYPES.get(attr, ('unknown', False))

        result[attr] = [TYPE_HANDLERS[action[0]](v) for v in values]
        result[attr] = result[attr] if not action[1] else result[attr][0]

    for attr, rules in ATTR_EXTEND.items():
        if attr in result:
            for new_key, transform in rules:
                if new_key.lower() in properties or '*' in properties:
                    result[new_key] = transform(result[attr])

    [result.pop(attr) for attr in properties_shadow if attr in result]

    return result


def search_object(connect, _logger, ldap_filter, search_base, properties, type_object,
                  search_scope: DS_TYPE_SCOPE = "subtree", only_one: bool = False):
    ldap_filter = DataDSLDAP[type_object.upper()].unit(ldap_filter)

    if only_one and '*' in ldap_filter:
        raise RuntimeError("При точеном поиске недопустим параметр разрешающий нестрогий поиск (*)")

    if not properties:
        properties = []

    properties_low = [i.lower() for i in properties]
    properties_shadow = []

    if '*' not in properties:
        if 'distinguishedName'.lower() not in properties_low:
            properties += ['distinguishedName']
        if 'distinguishedName'.lower() not in properties_low:
            properties += ['objectClass']

        for attr, attr_ext in ATTR_EXTEND.items():
            # Если дополнительный атрибут запрошен, пропускается
            if attr.lower() in properties_low:
                continue

            # Перебор дополнительных атрибутов
            for (name_ext, _) in attr_ext:
                if name_ext.lower() in properties_low:
                    properties_shadow += [attr.lower()]
                    properties += [attr.lower()]
                    break

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

    req_ctrl = SimplePagedResultsControl(criticality=False, size=1499, cookie='')

    msgid = connect.search_ext(
        base=search_base,
        scope=search_scope,
        filterstr=ldap_filter,
        attrlist=properties,
        serverctrls=[req_ctrl],
    )
    total_results = []
    pages = 0
    while True:
        pages += 1
        _, objects, _, server_sprc = connect.result3(msgid)

        for one_object in objects:
            if one_object[0]:
                total_results.append(object_processing(connect=connect, data=one_object[1],
                                                       properties=properties, properties_shadow=properties_shadow))

        pctrls = [c for c in server_sprc if c.controlType == SimplePagedResultsControl.controlType]
        if pctrls:
            if pctrls[0].cookie:  # Copy cookie from response control to request control
                req_ctrl.cookie = pctrls[0].cookie

                msgid = connect.search_ext(
                    base=search_base,
                    scope=search_scope,
                    filterstr=ldap_filter,
                    attrlist=properties,
                    serverctrls=[req_ctrl],
                )
            else:
                break
        else:
            break

    if only_one and len(total_results) == 0:
        raise RuntimeError("Объект не найден")
    elif only_one and len(total_results) > 1:
        raise RuntimeError("Найдено больше одного объекта")

    return total_results


def gen_filter_to_id(identity: str | DSDict, type_object: DS_TYPE_OBJECT_SYSTEM = "object",
                     return_dict: bool = False) -> str | DSDict:
    search_line: str

    if isinstance(identity, str):
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

    if return_dict:
        return identity

    if 'sAMAccountName' in identity and type_object in ["user", "computer", "group", "member"]:
        search_line = f"(sAMAccountName={identity['sAMAccountName']})"
    elif 'distinguishedName' in identity:
        search_line = f"(distinguishedName={ldap.filter.escape_filter_chars(identity['distinguishedName'])})"
    elif 'ObjectGUID' in identity:
        search_line = f"(ObjectGUID={identity['distinguishedName']})"
    elif 'objectSid' in identity:
        search_line = f"(objectSid={identity['objectSid']})"
    else:
        raise RuntimeError("В объекте нет подходящих атрибутов")

    return search_line


def c_sid_byte_to_string(data: bytes):
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


def c_datetime_unicode_to_python(data: bytes):
    return datetime.strptime(data.decode("utf-8"), "%Y%m%d%H%M%S.0Z")


def c_datetime_win_to_python(data: bytes):
    if data in [b'9223372036850000000', b'9223372036854775807', b'0']:
        return int(data.decode("utf-8"))

    return (datetime(1601, 1, 1, tzinfo=datetime.now().astimezone().tzinfo) +
            timedelta(seconds=int(data) / 10_000_000))


def return_groupscope(flags):
    if 'ACCOUNT_GROUP' in flags:
        return "Global"
    elif 'RESOURCE_GROUP' in flags:
        return "DomainLocal"
    elif 'UNIVERSAL_GROUP' in flags:
        return "Universal"
    return RuntimeError("Error Search Flag Group")


def c_bool_string_to_bool(data: str):
    if data == 'TRUE':
        return True
    elif data == 'FALSE':
        return False
    elif data is None:
        return None
    else:
        raise RuntimeError(f"Ошибка определения болевого значения: {data}")
