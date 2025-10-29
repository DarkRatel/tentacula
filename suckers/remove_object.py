from typing import Type
from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds import DSDict, DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | Type[DSDict]


def remove_object(login: str, password: str, host: str, identity: str | DSDict,
                  base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.remove_object(
            identity=identity

        )


create_post("remove_object", SpecData, remove_object, router_sucker)
