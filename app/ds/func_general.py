from datetime import datetime

from .data import DS_GROUP_SCOPE, DS_GROUP_CATEGORY
from .convertors_value import UAC_FLAGS, convert_grouptype


def gen_uac(uac: int, enabled: bool = None, password_never_expires: bool = None,
            account_not_delegated: bool = None, password_not_required: bool = None):
    if enabled is not None:
        if enabled:
            uac &= ~UAC_FLAGS['ACCOUNTDISABLE']
        else:
            uac |= UAC_FLAGS['ACCOUNTDISABLE']

    if password_never_expires is not None:
        if password_never_expires:
            uac |= UAC_FLAGS['DONT_EXPIRE_PASSWORD']
        else:
            uac &= ~UAC_FLAGS['DONT_EXPIRE_PASSWORD']

    if account_not_delegated is not None:
        if account_not_delegated:
            uac |= UAC_FLAGS['NOT_DELEGATED']
        else:
            uac &= ~UAC_FLAGS['NOT_DELEGATED']

    if password_not_required is not None:
        if password_not_required:
            uac |= UAC_FLAGS['PASSWD_NOTREQD']
        else:
            uac &= ~UAC_FLAGS['PASSWD_NOTREQD']

    return uac


def gen_change_pwd_at_logon(change_password_at_logon: bool):
    return '0' if change_password_at_logon else '-1'


def gen_account_exp_date(account_expiration_date: bool | datetime | str = None):
    if isinstance(account_expiration_date, str):
        account_expiration_date = datetime.fromisoformat(account_expiration_date)

    if isinstance(account_expiration_date, datetime):
        value = str(
            int(
                (
                        account_expiration_date -
                        datetime(1601, 1, 1) -
                        datetime.now().astimezone().tzinfo.utcoffset(None)
                ).total_seconds() * 10_000_000
            )
        )
    elif isinstance(account_expiration_date, bool) and account_expiration_date is False:
        value = "0"
    else:
        raise RuntimeError("account_expiration_date must be datetime or False")

    return value


def gen_gt(gt: int, group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None):
    gt = convert_grouptype(gt)

    flags = ['RESOURCE_GROUP', 'ACCOUNT_GROUP', 'UNIVERSAL_GROUP']

    if group_scope:
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

    if group_category:
        if group_category == "Security":
            gt += ['SECURITY_ENABLED']
        elif group_category == "Distribution":
            gt = [i for i in gt if i != 'SECURITY_ENABLED']
        else:
            raise RuntimeError("group_category must be 'Security' or 'Distribution'")

    gt = list(set(gt))

    return convert_grouptype(gt)
