from datetime import datetime
from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | dict
    remove: dict = None
    add: dict[str, list] = None
    replace: dict[str, list] = None
    clear: list[str] = None
    display_name: str = None
    sam_account_name: str = None
    user_principal_name: str = None
    enabled: bool = None
    password_never_expires: bool = None
    account_not_delegated: bool = None
    change_password_at_logon: bool = None
    account_expiration_date: bool | datetime = None


async def set_user(login: str, password: str, host: str, identity: str | dict, base: str = None,
                   remove: dict = None, add: dict[str, list] = None,
                   replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                   sam_account_name: str = None, user_principal_name: str = None, enabled: bool = None,
                   password_never_expires: bool = None, account_not_delegated: bool = None,
                   change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.set_user(
            identity=identity,
            remove=remove,
            add=add,
            replace=replace,
            clear=clear,
            display_name=display_name,
            sam_account_name=sam_account_name,
            user_principal_name=user_principal_name,
            enabled=enabled,
            password_never_expires=password_never_expires,
            account_not_delegated=account_not_delegated,
            change_password_at_logon=change_password_at_logon,
            account_expiration_date=account_expiration_date
        )


create_post("set_user", SpecData, set_user, router_ds)
