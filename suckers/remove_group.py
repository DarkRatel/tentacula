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


def remove_group(login: str, password: str, host: str, identity: str | DSDict, base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.remove_group(
            identity=identity
        )


create_post("remove_group", SpecData, remove_group, router_ds)
