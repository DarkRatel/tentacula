"""
Функции генерации атрибутов, для изменения которых должна быть специальная обработка значения
"""
from datetime import datetime

from .data import DS_GROUP_SCOPE, DS_GROUP_CATEGORY
from .convertors_value import _UAC_FLAGS, convert_grouptype


def gen_uac(uac: int, enabled: bool = None, password_never_expires: bool = None,
            account_not_delegated: bool = None, password_not_required: bool = None) -> int:
    """
    Формирование userAccountControl на основе входящего значения с учётом новых ключей.
    Ключи флагов учитываются, если было передано булевое значение.
    userAccountControl хранится в байтах, поэтому в десятеричное значение добавляется байт
    и убирается в зависимости от специфики флага

    Args:
        uac: Исходное значения userAccountControl. Допустимо передать 0
        enabled: Добавить флаг включения или отключения объекта
        password_never_expires: Включение бессрочного пароля
        account_not_delegated: Включение запрета на делегирование
        password_not_required: Включение пустого пароля
    """
    if enabled is not None:
        if enabled:
            uac &= ~_UAC_FLAGS['ACCOUNTDISABLE']
        else:
            uac |= _UAC_FLAGS['ACCOUNTDISABLE']

    if password_never_expires is not None:
        if password_never_expires:
            uac |= _UAC_FLAGS['DONT_EXPIRE_PASSWORD']
        else:
            uac &= ~_UAC_FLAGS['DONT_EXPIRE_PASSWORD']

    if account_not_delegated is not None:
        if account_not_delegated:
            uac |= _UAC_FLAGS['NOT_DELEGATED']
        else:
            uac &= ~_UAC_FLAGS['NOT_DELEGATED']

    if password_not_required is not None:
        if password_not_required:
            uac |= _UAC_FLAGS['PASSWD_NOTREQD']
        else:
            uac &= ~_UAC_FLAGS['PASSWD_NOTREQD']

    return uac


def gen_change_pwd_at_logon(change_password_at_logon: bool) -> str:
    """
    Функция формирования значения, указывающего на необходимость, сменить пароль при входе.
    Значение будет равно 0 если пароль необходимо сменить и -1 если изменение пароля не требуется

    Args:
        change_password_at_logon: Сменить пароль при входе.
    """
    return '0' if change_password_at_logon else '-1'


def gen_account_exp_date(account_expiration_date: bool | datetime | str = None) -> str:
    """
    Функция формирования значения срока действия объекта. Строка и datetime считаются датой срока действия объекта,
    False отключает ограничение

    Args:
        account_expiration_date: Указатель нового значения
    """
    # Если была передана строка, то она будет конвертирована в datetime, для обработки
    if isinstance(account_expiration_date, str):
        account_expiration_date = datetime.fromisoformat(account_expiration_date)

    # Обработка datetime
    if isinstance(account_expiration_date, datetime):
        return str(
            int(
                (
                        account_expiration_date -
                        datetime(1601, 1, 1) -
                        datetime.now().astimezone().tzinfo.utcoffset(None)
                ).total_seconds() * 10_000_000
            )
        )
    # Если было значение для отключения ограничения
    elif isinstance(account_expiration_date, bool) and account_expiration_date is False:
        return "0"
    else:
        raise RuntimeError("account_expiration_date must be datetime or False")


def gen_gt(gt: int, group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None) -> int:
    """
    Формирование groupType на основе входящего значения с учётом новых ключей.
    Ключи флагов учитываются, если было передано булевое значение.
    groupType хранится в байтах, поэтому в десятеричное значение добавляется байт
    и убирается в зависимости от специфики флага

    Args:
        gt: Исходное значения groupType. Допустимо передать 0
        group_scope: Область группы
        group_category: Категория группы
    """
    # Конвертирование значения в набор флагов
    gt = convert_grouptype(gt)

    # Если передано значение области группы, то в groupType остаётся только выбранный флаг, остальные удаляются
    if group_scope:
        flags = ['RESOURCE_GROUP', 'ACCOUNT_GROUP', 'UNIVERSAL_GROUP']
        if group_scope == "DomainLocal":
            add = 'RESOURCE_GROUP'
        elif group_scope == "Global":
            add = 'ACCOUNT_GROUP'
        elif group_scope == "Universal":
            add = 'UNIVERSAL_GROUP'
        else:
            raise RuntimeError("group_scope must be 'DomainLocal' or 'Global' or 'Universal'")

        flags.remove(add)

        gt = [i for i in gt if i not in flags]
        gt += [add]

    # Если передано значение категории группы, то изменяется флаг категории (флаг добавляется или убирается
    if group_category:
        if group_category == "Security":
            gt += ['SECURITY_ENABLED']
        elif group_category == "Distribution":
            gt = [i for i in gt if i != 'SECURITY_ENABLED']
        else:
            raise RuntimeError("group_category must be 'Security' or 'Distribution'")

    # Удаления дублирования флагов
    gt = list(set(gt))

    # Возращение значения в виде десятеричного числа
    return convert_grouptype(gt)
