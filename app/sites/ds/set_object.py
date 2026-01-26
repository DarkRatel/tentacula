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
    remove: dict = None
    add: dict[str, list] = None
    replace: dict[str, list] = None
    clear: list[str] = None
    display_name: str = None


async def set_object(login: str, password: str, host: str, identity: str | DSDict,
                     base: str = None, remove: dict = None, add: dict[str, list] = None,
                     replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.set_object(
            identity=identity,
            remove=remove,
            add=add,
            replace=replace,
            clear=clear,
            display_name=display_name
        )


create_post("set_object", SpecData, set_object, router_ds)
