from typing import Type
from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds import DSDict, DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    port: int = 636
    base: str = None

    identity: str | Type[DSDict]
    account_password: str


def set_account_password(login: str, password: str, host: str, identity: str | DSDict, account_password: str,
                         port: int = 636, base: str = None):
    with DSHook(login=login, password=password, host=host, port=port, base=base) as ds:
        ds.set_account_password(
            identity=identity,
            account_password=account_password
        )


create_post("set_account_password", SpecData, set_account_password, router_sucker)
