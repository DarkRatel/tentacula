import ldap

from .ds_dict import DSDict
from .func_ds_get import search_object, gen_filter_to_id
from .func_general import gen_uac, gen_gt, gen_change_pwd_at_logon, gen_account_exp_date


def handler_uac(value, base_value):
    return str(gen_uac(value,
                       enabled=base_value.get('Enabled', None),
                       password_never_expires=base_value.get('PasswordNeverExpires', None),
                       account_not_delegated=base_value.get('AccountNotDelegated', None),
                       password_not_required=base_value.get('PasswordNotRequired', None)))


def handler_gt(value, base_value):
    return str(gen_gt(value, group_scope=base_value.get('GroupScope', None),
                      group_category=base_value.get('GroupCategory', None)))


def handler_change_pwd_at_logon(_, value):
    return gen_change_pwd_at_logon(value)


def handler_account_exp_date(_, value):
    return gen_account_exp_date(value)


def handler_default(_, value):
    return value


ATTR_PROCESSING = DSDict({
    'userAccountControl': handler_uac,
    'groupType': handler_gt,
    'pwdLastSet': handler_change_pwd_at_logon,
    'accountExpires': handler_account_exp_date,
    '_default_': handler_default,
})


def ds_set(connect, _logger, type_object, identity, base, dry_run: bool,
           remove: dict[str, list] | None = None, add: dict[str, list] | None = None,
           replace: dict[str, list] | None = None, clear: list | tuple | None = None,
           special: dict | None = None):
    list_object = []

    if remove:
        for key, value in remove.items():
            list_object.append((ldap.MOD_DELETE, key, value))

    if add:
        for key, value in add.items():
            list_object.append((ldap.MOD_ADD, key, value))

    if replace:
        for key, value in replace.items():
            list_object.append((ldap.MOD_REPLACE, key, value))

    if clear:
        for key in clear:
            list_object.append((ldap.MOD_DELETE, key, None))

    special_attr = []
    for key, value in special.items():
        for (_, k, _) in list_object:
            if k.lower() == key.lower():
                raise RuntimeError(f"Недопустимо менять атрибут {key} как настраиваемый и дополнительный")
        if value is not None:
            special_attr += [key]

    result = search_object(
        connect=connect,
        _logger=_logger,
        ldap_filter=gen_filter_to_id(identity, type_object=type_object),
        search_base=base,
        properties=[k for (_, k, _) in list_object] + special_attr,
        type_object=type_object,
        only_one=True
    )[0]

    for key in special_attr:
        handler = ATTR_PROCESSING.get(key, ATTR_PROCESSING['_default_'])

        result[key] = [handler(result[key], special[key])]
        print(result[key])

        if key in result:
            list_object.append((ldap.MOD_REPLACE, key, result[key]))
        else:
            list_object.append((ldap.MOD_ADD, key, result[key]))

    if not list_object:
        raise RuntimeError("Нет данных для изменения")

    temp = []
    for (action, key, values) in list_object:
        if values is None:
            temp += [(action, key, None)]
        elif key.lower() == 'unicodePwd'.lower():
            temp += [(action, key, [f'"{v}"'.encode("utf-16-le") for v in values])]
        else:
            temp += [(action, key, [v.encode("utf-8") for v in values])]
    list_object = temp

    _logger.info(f"Set {type_object}: DN: {result['distinguishedName']}, "
                 f"new value: {[(a, ['***'] if k.lower() == 'unicodepwd' else v, v) for a, k, v in list_object]}, "
                 f"old value: {result}")

    if not dry_run:
        connect.modify_s(result['distinguishedName'], list_object)
    else:
        _logger.warning("Enabled dry run")
