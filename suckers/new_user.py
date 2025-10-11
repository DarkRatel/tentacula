from typing import Type
from datetime import datetime
from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds.ds_dict import DSDict
from ds.ds_hook import DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    port: int = 636
    base: str = None

    path: str
    name: str
    samaccountname: str
    account_password: str
    userprincipalname: str = None
    enabled: bool = None
    password_never_expires: bool = None
    account_not_delegated: bool = None
    change_password_at_logon: bool = None
    account_expiration_date: bool | datetime = None
    other_attributes: dict[str, list] = None


def new_user(login: str, password: str, host: str, path: str, name: str, samaccountname: str, account_password: str,
             userprincipalname: str = None,
             enabled: bool = None, password_never_expires: bool = None, account_not_delegated: bool = None,
             change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None,
             other_attributes: dict[str, list] = None, port: int = 636, base: str = None):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        ds.new_user(
            path=path,
            name=name,
            samaccountname=samaccountname,
            account_password=account_password,
            userprincipalname=userprincipalname,
            enabled=enabled,
            password_never_expires=password_never_expires,
            account_not_delegated=account_not_delegated,
            change_password_at_logon=change_password_at_logon,
            account_expiration_date=account_expiration_date,
            other_attributes=other_attributes

        )


create_post("new_user", SpecData, new_user, router_sucker)
