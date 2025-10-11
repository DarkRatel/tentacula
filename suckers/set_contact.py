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
    remove: dict = None
    add: dict[str, list] = None
    replace: dict[str, list] = None
    clear: list[str] = None
    display_name: str = None


def set_contact(login: str, password: str, host: str, identity: str | DSDict, port: int = 636, base: str = None,
                remove: dict = None, add: dict[str, list] = None,
                replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        ds.set_contact(
            identity=identity,
            remove=remove,
            add=add,
            replace=replace,
            clear=clear,
            display_name=display_name,

        )


create_post("set_contact", SpecData, set_contact, router_sucker)
