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


async def get_group_member(login: str, password: str, host: str, identity: str | DSDict,
                           base: str = None) -> list[DSDict]:
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        result = ds.get_group_member(
            identity=identity
        )

    return result


create_post("get_group_member", SpecData, get_group_member, router_ds)
