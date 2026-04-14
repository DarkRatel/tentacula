from datetime import datetime
from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSHook
from app.systems.config import AppConfig


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None
    log_level: int = None

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
                   remove: dict[str, list | bool | str] = None, add: dict[str, list | bool | str] = None,
                   replace: dict[str, list | bool | str] = None, clear: list[str] = None,
                   display_name: str = None, sam_account_name: str = None, user_principal_name: str = None,
                   enabled: bool = None, password_never_expires: bool = None, account_not_delegated: bool = None,
                   change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None,
                   log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
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


create_post(endpoint="set_user", func=set_user, access=AppConfig.SUCKERS_DS__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_ds)
