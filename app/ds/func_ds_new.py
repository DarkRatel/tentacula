from datetime import datetime

import ldap

from .ds_dict import DSDict
from .data import DataDSLDAP, DataDSProperties, DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY
from .func_ds_get import search_object, gen_filter_to_id, ATTR_EXTEND
from .ds_function import search_root_dse
from .convertors_value import UAC_FLAGS, convert_object_class


def ds_new(connect, _logger, type_object: DS_TYPE_OBJECT, path: str, name: str, display_name: str = None,
           extend: dict[str, list] = None, other_attributes: dict[str, list] = None) -> None:
    dn = f"CN={ldap.dn.escape_dn_chars(name)},{path}"

    dict_object = DSDict()
    dict_object['objectClass'] = convert_object_class(name=type_object)

    dict_object.update({'cn': [name], 'name': [name]})

    if display_name:
        dict_object.update({'displayName': [name]})

    if extend:
        dict_object.update(**extend)

    if other_attributes:
        for key, value in other_attributes.items():
            if key in dict_object:
                raise RuntimeError(f"Атрибут {key} уже был определён. Удалите его из other_attributes")
        dict_object.update(**other_attributes)

    _logger.info(f"New {type_object}: DN: {dn}, value: {dict_object}")

    for key, values in dict_object.items():
        if key.lower() == 'unicodePwd'.lower():
            dict_object[key] = [f'"{v}"'.encode("utf-16-le") for v in values]
        else:
            dict_object[key] = [v.encode("utf-8") for v in values]

    connect.add_s(dn, [(key, value) for key, value in dict_object.items()])
