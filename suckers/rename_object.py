from typing import Type
from datetime import datetime
from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds.ds_dict import DSDict
from ds.ds_hook import DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    port: int = 636
    base: str = None

    identity: str | Type[DSDict]
    new_name: str


def rename_object(login: str, password: str, host: str, identity: str | DSDict, new_name: str,
                  port: int = 636, base: str = None):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        ds.rename_object(
            identity=identity,
            new_name=new_name

        )


create_post("rename_object", SpecData, rename_object, router_sucker)
