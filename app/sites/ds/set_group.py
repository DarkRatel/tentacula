from typing import Type
from datetime import datetime
from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSDict, DSHook, DS_GROUP_SCOPE, DS_GROUP_CATEGORY


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
    group_scope: DS_GROUP_SCOPE = None
    group_category: DS_GROUP_CATEGORY = None


def set_group(login: str, password: str, host: str, identity: str | DSDict, base: str = None,
              remove: dict = None,
              add: dict[str, list] = None,
              replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
              group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.set_group(
            identity=identity,
            remove=remove,
            add=add,
            replace=replace,
            clear=clear,
            display_name=display_name,
            group_scope=group_scope,
            group_category=group_category

        )


create_post("set_group", SpecData, set_group, router_ds)
