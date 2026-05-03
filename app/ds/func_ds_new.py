"""
Функция создания объектов в СК

Обработка атрибутов вынесена за приделы функции.
Есть существенное отличие обработки специальных параметров (их обработка происходит в не функции)
Поскольку при создании не требуется сперва получать исходный объект, поэтому есть отличия от изменения объектов
"""
import ldap

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

    # Формирование списка и обязательного аттрибута.
    # Получение набора ключей создаваемого объекта на основе короткого имени
    list_object = [('objectClass', convert_object_class(name=type_object))]

    # cn, name и distinguishedName принудительно используют одно имя
    list_object.extend([('cn', [name]), ('name', [name])])

    if display_name:
        list_object.append(('displayName', [display_name]))

    # Ожидается, что специальные атрибуты (обработанные до передачи в функцию) уже обработаны
    if extend:
        for key, value in extend.items():
            list_object.append((key, value))

    # Проверка, что дополнительные атрибуты не были переданы через ключи ранее и добавление атрибута в общий список
    if other_attributes:
        for key, value in other_attributes.items():
            for (_, k, _) in list_object:
                if k.lower() == key.lower():
                    raise ValueError(f"Атрибут {key} уже был определён. Удалите его из other_attributes")
            list_object.append((key, convert_value(key, value)))

    _logger.info(f"New {type_object}: DN: {dn}, "
                 f"value: {[(k, ['***'] if k.lower() == 'unicodepwd' else v) for k, v in list_object]}")

    # Перебор всех значений для проверки являются ли они списком и конвертация в UTF
    for index, (key, values) in enumerate(list_object):
        if not isinstance(values, list):
            raise ValueError(f"In {key} not list")

        if key.lower() == 'unicodePwd'.lower():
            list_object[index] = (key, [f'"{v}"'.encode("utf-16-le") for v in values])
        else:
            list_object[index] = (key, [v.encode("utf-8") for v in values])

    _logger.debug(f"New {type_object}: DN: {dn}, "
                  f"value: {[(k, ['***'] if k.lower() == 'unicodepwd' else v) for k, v in list_object]}")

    if not dry_run:
        connect.add_s(dn, list_object)
    else:
        _logger.warning("Enabled dry run")
