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


def remove_user(login: str, password: str, host: str, identity: str | DSDict,
                port: int = 636, base: str = None):
    with DSHook(login=login, password=password, host=host, port=port, base=base) as ds:
        ds.remove_user(
            identity=identity

        )


create_post("remove_user", SpecData, remove_user, router_sucker)
