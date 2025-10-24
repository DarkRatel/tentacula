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
    members: str | Type[DSDict] | list[str] | tuple[str] | list[Type[DSDict]]


def add_group_member(login: str, password: str, host: str, identity: str | DSDict,
                     members: str | DSDict | list[str] | tuple[str] | list[DSDict],
                     port: int = 636, base: str = None):
    with DSHook(login=login, password=password, host=host, port=port, base=base) as ds:
        ds.add_group_member(
            identity=identity,
            members=members
        )


create_post("add_group_member", SpecData, add_group_member, router_sucker)
