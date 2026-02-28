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


async def remove_computer(login: str, password: str, host: str, identity: str | dict, base: str = None,
                          log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        ds.remove_computer(
            identity=identity
        )


create_post("remove_computer", SpecData, remove_computer, router_ds)
