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


async def remove_object(login: str, password: str, host: str, identity: str | dict, base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.remove_object(
            identity=identity
        )


create_post("remove_object", SpecData, remove_object, router_ds)
