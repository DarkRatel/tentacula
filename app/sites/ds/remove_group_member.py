from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | dict
    members: str | dict | list[str] | tuple[str] | list[dict]


async def remove_group_member(login: str, password: str, host: str, identity: str | dict,
                              members: str | dict | list[str] | tuple[str] | list[dict], base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.remove_group_member(
            identity=identity,
            members=members
        )


create_post("remove_group_member", SpecData, remove_group_member, router_ds)
