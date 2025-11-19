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

    path: str
    name: str
    sam_account_name: str
    account_password: str
    user_principal_name: str = None
    enabled: bool = None
    password_never_expires: bool = None
    account_not_delegated: bool = None
    change_password_at_logon: bool = None
    account_expiration_date: bool | datetime = None
    other_attributes: dict[str, list] = None


def new_user(login: str, password: str, host: str, path: str, name: str, sam_account_name: str, account_password: str,
             user_principal_name: str = None, enabled: bool = None, password_never_expires: bool = None,
             account_not_delegated: bool = None, change_password_at_logon: bool = None,
             account_expiration_date: bool | datetime = None, other_attributes: dict[str, list] = None,
             base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.new_user(
            path=path,
            name=name,
            sam_account_name=sam_account_name,
            account_password=account_password,
            user_principal_name=user_principal_name,
            enabled=enabled,
            password_never_expires=password_never_expires,
            account_not_delegated=account_not_delegated,
            change_password_at_logon=change_password_at_logon,
            account_expiration_date=account_expiration_date,
            other_attributes=other_attributes
        )


create_post("new_user", SpecData, new_user, router_ds)
