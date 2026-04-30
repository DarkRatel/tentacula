"""
Функция создания объектов в СК

Обработка атрибутов вынесена за приделы функции.
Есть существенное отличие обработки специальных параметров (их обработка происходит в не функции)
Поскольку при создании не требуется сперва получать исходный объект
"""
import ldap

from .ds_dict import DSDict
from .data import DS_TYPE_OBJECT
from .convertors_value import convert_object_class, convert_value


def ds_new(connect, _logger, dry_run: bool, type_object: DS_TYPE_OBJECT, path: str, name: str, display_name: str = None,
           extend: dict[str, list | bool] = None, other_attributes: dict[str, list | str | bool] = None) -> None:
    """
    Функция создания объекта в СК

    Args:
        connect: Переменная с открытой сессией к СК
        _logger: Переменная с логированием
        dry_run: Запуск без внесения изменений в СК
        type_object: Тип объекта
        path: Область создания папки
        name: Имя объекта (поля cn и name)
        display_name: Выводимое имя
        extend: Список атрибутов, сформированных через отдельные ключи
        other_attributes: Дополнительные атрибуты, полученные не через специальные ключи
    """
    # Формирование distinguishedName и изоляция специальных символов
    dn = f"CN={ldap.dn.escape_dn_chars(name)},{path}"

    dict_object = DSDict()
    # Получение набора ключей создаваемого объекта на основе короткого имени
    dict_object['objectClass'] = convert_object_class(name=type_object)

    dict_object.update({'cn': [name], 'name': [name]})

    if display_name:
        dict_object.update({'displayName': [display_name]})

    if extend:
        dict_object.update(**extend)

    if other_attributes:
        for key, value in other_attributes.items():
            if key in dict_object:
                raise ValueError(f"Атрибут {key} уже был определён. Удалите его из other_attributes")
            dict_object.update({key: convert_value(key, value)})

    _logger.info(f"New {type_object}: DN: {dn}, "
                 f"value: { {k: ['***'] if k.lower() == 'unicodepwd' else v for k, v in dict_object.items()} }")

    for key, values in dict_object.items():
        if key.lower() == 'unicodePwd'.lower():
            dict_object[key] = [f'"{v}"'.encode("utf-16-le") for v in values]
        else:
            dict_object[key] = [v.encode("utf-8") for v in values]

    _logger.debug(f"New {type_object}: DN: {dn}, "
                  f"value: { {k: ['***'] if k.lower() == 'unicodepwd' else v for k, v in dict_object.items()} }")

    if not dry_run:
        connect.add_s(dn, [(key, value) for key, value in dict_object.items()])
    else:
        _logger.warning("Enabled dry run")
