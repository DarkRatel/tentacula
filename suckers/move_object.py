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
    target_path: str


def move_object(login: str, password: str, host: str, identity: str | DSDict, target_path: str, base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.move_object(
            identity=identity,
            target_path=target_path
        )


create_post("move_object", SpecData, move_object, router_ds)
