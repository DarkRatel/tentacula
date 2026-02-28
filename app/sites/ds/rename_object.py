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
    new_name: str


async def rename_object(login: str, password: str, host: str, identity: str | dict, new_name: str,
                        base: str = None, log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        ds.rename_object(
            identity=identity,
            new_name=new_name
        )


create_post("rename_object", SpecData, rename_object, router_ds)
