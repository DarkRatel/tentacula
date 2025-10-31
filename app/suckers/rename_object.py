from typing import Type
from pydantic import BaseModel

from app.moduls.post_base import create_post
from app.sites.suckers import router_sucker
from app.ds import DSDict, DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | Type[DSDict]
    new_name: str


def rename_object(login: str, password: str, host: str, identity: str | DSDict, new_name: str,
                  base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.rename_object(
            identity=identity,
            new_name=new_name
        )


create_post("rename_object", SpecData, rename_object, router_sucker)
