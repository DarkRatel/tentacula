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
    target_path: str


async def move_object(login: str, password: str, host: str, identity: str | dict, target_path: str, base: str = None,
                      log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        ds.move_object(
            identity=identity,
            target_path=target_path
        )


create_post("move_object", SpecData, move_object, router_ds)
