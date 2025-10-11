from typing import Type

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


def get_group_member(login: str, password: str, host: str, identity: str | DSDict,
                     port: int = 636, base: str = None):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        result = ds.get_group_member(
            identity=identity
        )

    return result


create_post("get_group_member", SpecData, get_group_member, router_sucker)
