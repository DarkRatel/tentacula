from typing import Type
from datetime import datetime
from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds.ds_dict import DSDict
from ds.ds_hook import DSHook, DS_GROUP_SCOPE, DS_GROUP_CATEGORY


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    port: int = 636
    base: str = None

    identity: str | Type[DSDict]


def set_account_unlock(login: str, password: str, host: str, identity: str | DSDict,
                       port: int = 636, base: str = None):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        ds.set_account_unlock(
            identity=identity

        )


create_post("set_account_unlock", SpecData, set_account_unlock, router_sucker)
