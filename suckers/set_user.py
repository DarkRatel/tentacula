from typing import Type
from datetime import datetime
from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds.ds_dict import DSDict
from ds.ds_hook import DSHook, DS_TYPE_OBJECT, DS_TYPE_SCOPE


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    port: int = 636
    base: str = None

    identity: str | Type[DSDict]
    remove: dict = None
    add: dict[str, list] = None
    replace: dict[str, list] = None
    clear: list[str] = None
    display_name: str = None
    samaccountname: str = None
    serprincipalname: str = None
    enabled: bool = None
    password_never_expires: bool = None
    account_not_delegated: bool = None
    change_password_at_logon: bool = None
    account_expiration_date: bool | datetime = None


def set_user(login: str, password: str, host: str, identity: str | DSDict, port: int = 636, base: str = None,
             remove: dict = None, add: dict[str, list] = None,
             replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
             samaccountname: str = None, userprincipalname: str = None, enabled: bool = None,
             password_never_expires: bool = None, account_not_delegated: bool = None,
             change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        ds.set_user(
            identity=identity,
            remove=remove,
            add=add,
            replace=replace,
            clear=clear,
            display_name=display_name,
            samaccountname=samaccountname,
            userprincipalname=userprincipalname,
            enabled=enabled,
            password_never_expires=password_never_expires,
            account_not_delegated=account_not_delegated,
            change_password_at_logon=change_password_at_logon,
            account_expiration_date=account_expiration_date
        )


create_post("set_user", SpecData, set_user, router_sucker)
