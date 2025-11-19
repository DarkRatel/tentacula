from typing import Type
from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSDict, DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | Type[DSDict]


def set_account_unlock(login: str, password: str, host: str, identity: str | DSDict,
                       port: int = 636, base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.set_account_unlock(
            identity=identity
        )


create_post("set_account_unlock", SpecData, set_account_unlock, router_ds)
