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

    path: str
    name: str
    other_attributes: dict[str, list] = None


async def new_contact(login: str, password: str, host: str, path: str, name: str,
                      other_attributes: dict[str, list] = None, base: str = None, log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        ds.new_contact(
            path=path,
            name=name,
            other_attributes=other_attributes
        )


create_post("new_contact", SpecData, new_contact, router_ds)
