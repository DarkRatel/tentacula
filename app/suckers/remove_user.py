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


def remove_user(login: str, password: str, host: str, identity: str | DSDict,
                base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.remove_user(
            identity=identity

        )


create_post("remove_user", SpecData, remove_user, router_sucker)
