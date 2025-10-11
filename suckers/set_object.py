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

    identity: str | Type[DSDict] = None
    remove: dict = None
    add: dict[str, list] = None
    replace: dict[str, list] = None
    clear: list[str] = None
    display_name: str = None


def set_object(login: str, password: str, host: str, port: int = 636, base: str = None,
               identity: str | DSDict = None, remove: dict = None, add: dict[str, list] = None,
               replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        result = ds.set_object(
            identity=identity,
            remove=remove,
            add=add,
            replace=replace,
            clear=clear,
            display_name=display_name
        )

    return result


create_post("set_object", SpecData, set_object, router_sucker)
