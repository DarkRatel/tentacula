from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None
    log_level: int = None

    identity: str | dict
    members: str | dict | list[str] | tuple[str] | list[dict]


async def add_group_member(login: str, password: str, host: str, identity: str | dict,
                           members: str | dict | list[str] | tuple[str] | list[dict], base: str = None,
                           log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        ds.add_group_member(
            identity=identity,
            members=members
        )


create_post("add_group_member", SpecData, add_group_member, router_ds)
