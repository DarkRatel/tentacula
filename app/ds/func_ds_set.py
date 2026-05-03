"""
Функция изменения объектов в СК

Есть существенное отличие обработки специальных параметров (их обработка происходит в не функции)
Поскольку при изменении не требуется сперва получать исходный объект, поэтому есть отличия от создания объектов
"""
import ldap
from datetime import datetime

from .data import DS_TYPE_OBJECT_SYSTEM
from .ds_dict import DSDict
from .func_ds_get import search_object, gen_filter_to_id
from .func_general import gen_uac, gen_gt, gen_change_pwd_at_logon, gen_account_exp_date
from .convertors_value import convert_value


def handler_uac(source: int, new_value: dict[str, bool | None]) -> str:
    """Функция формирования атрибута userAccountControl на основе исходного значения"""
    return str(gen_uac(source,
                       enabled=new_value.get('Enabled', None),
                       password_never_expires=new_value.get('PasswordNeverExpires', None),
                       account_not_delegated=new_value.get('AccountNotDelegated', None),
                       password_not_required=new_value.get('PasswordNotRequired', None)))


def handler_gt(source: int, new_value: dict[str, bool | None]) -> str:
    """Функция формирования атрибута groupType на основе исходного значения"""
    return str(gen_gt(source, group_scope=new_value.get('GroupScope', None),
                      group_category=new_value.get('GroupCategory', None)))


def handler_change_pwd_at_logon(_, value: bool):
    """Функция формирования указателя на сброс пароля. Ключ <исходного значения> не учитывается"""
    return gen_change_pwd_at_logon(value)


def handler_account_exp_date(_, value: bool | datetime | str):
    """Функция формирования указателя значения для срока действия пользователя.
    Ключ <исходного значения> не учитывается"""
    return gen_account_exp_date(value)


def handler_default(_, value):
    """Функция для всех атрибутов, под которые не были найдены подходящие обработки.
    Ключ <исходного значения> не учитывается"""
    return value


# Словарь с функциями специфичной обработки функций.
# Каждая функция должна учитывать исходное значение аттрибута как первый ключ и новое значение как второй ключ
ATTR_PROCESSING = DSDict({
    'userAccountControl': handler_uac,
    'groupType': handler_gt,
    'pwdLastSet': handler_change_pwd_at_logon,
    'accountExpires': handler_account_exp_date,
    '_default_': handler_default,
})


def ds_set(connect, _logger, type_object: DS_TYPE_OBJECT_SYSTEM, dry_run: bool,
           identity: str | DSDict | dict, base: str, remove: dict[str, list | str | bool] | None = None,
           add: dict[str, list | str | bool] | None = None, replace: dict[str, list | str | bool] | None = None,
           clear: list | tuple | None = None, special: dict | None = None) -> None:
    """
    Функция изменения объекта

    Args:
        connect: Переменная с открытой сессией к СК
        _logger: Переменная с логированием
        type_object: Тип объекта
        dry_run: Запуск без внесения изменений в СК
        identity: Уникальный идентификатор редактируемого объекта
        base: Область поиска редактируемого объекта в СК
        remove: Словарь атрибутов из которых будут удаляться переданные значения
        add: Словарь атрибутов, в которые будут добавляться переданные атрибуты;
        replace: Словарь атрибутов, в которых значения будут заменены на переданные
        clear: Список атрибутов, которые будут отчищены
        special: Словарь со специальными атрибутами, которые должны быть обработаны
    """

    # Переменна для формирования списка атрибутов на изменение
    list_object = []

    # Обработка атрибутов для удаления значений
    if remove:
        for key, value in remove.items():
            list_object.append((ldap.MOD_DELETE, key, convert_value(key, value)))

    # Обработка атрибутов для добавления значений
    if add:
        for key, value in add.items():
            list_object.append((ldap.MOD_ADD, key, convert_value(key, value)))

    # Обработка атрибутов для замены значений
    if replace:
        for key, value in replace.items():
            list_object.append((ldap.MOD_REPLACE, key, convert_value(key, value)))

    # Обработка атрибутов отчистки значений
    if clear:
        for key in clear:
            list_object.append((ldap.MOD_DELETE, key, None))

    # Обработка специальных атрибутов
    special_attr = []
    if special:
        for key, value in special.items():
            for (_, k, _) in list_object:
                if k.lower() == key.lower():
                    raise ValueError(f"Атрибут {key} уже был определён. Удалите дублирование")
            if value is not None:
                special_attr.append(key)

    # Запрос исходного объекта со всеми атрибутами, которые планируется изменять. Если объект не найден, это ошибка
    result = search_object(
        connect=connect,
        _logger=_logger,
        ldap_filter=gen_filter_to_id(identity, type_object=type_object),
        search_base=base,
        properties=[k for (_, k, _) in list_object] + special_attr,
        type_object=type_object,
        only_one=True
    )[0]

    # С учётом полученных результатов, специальные атрибуты обрабатываются исходя из исходных значений
    for key in special_attr:
        # Если атрибут не был получен, значит он не заполнен, поэтому значение будет не заменено, а добавлено
        if key in result:
            # Если для атрибута не найдена особая обработка, используется обработка по умолчанию
            handler = ATTR_PROCESSING.get(key, ATTR_PROCESSING['_default_'])
            value = handler(result[key], special[key])
            action = ldap.MOD_REPLACE
        else:
            value = special[key]
            action = ldap.MOD_ADD

        # Добавления атрибута в общий список
        list_object.append((action, key, convert_value(key, value)))

    # Если список атрибутов для изменения не был сформирован, обработка прерывается
    if not list_object:
        raise ValueError("Нет данных для изменения")

    _logger.info(f"Set {type_object}: DN: {result['distinguishedName']}, "
                 f"new value: {[(a, k, ['***'] if k.lower() == 'unicodepwd' else v) for a, k, v in list_object]}, "
                 f"old value: {result}")

    # Проверка значений и конвертация значений в UTF
    for index, (action, key, values) in enumerate(list_object):
        # Проверка, что сформирован список из значений
        if not isinstance(values, list):
            raise ValueError(f"In {key} not list or None")

        if values is None:
            list_object[index] = [(action, key, None)]
        elif key.lower() == 'unicodePwd'.lower():
            list_object[index] = [(action, key, [f'"{v}"'.encode("utf-16-le") for v in values])]
        else:
            list_object[index] = [(action, key, [v.encode("utf-8") for v in values])]

    _logger.debug(f"Set {type_object}: DN: {result['distinguishedName']}, "
                  f"new value: {[(a, k, ['***'] if k.lower() == 'unicodepwd' else v) for a, k, v in list_object]}, "
                  f"old value: {result}")

    if not dry_run:
        connect.modify_s(result['distinguishedName'], list_object)
    else:
        _logger.warning("Enabled dry run")
