from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds import DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    path: str
    name: str
    other_attributes: dict[str, list] = None


def new_contact(login: str, password: str, host: str, path: str, name: str, other_attributes: dict[str, list] = None,
                base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.new_contact(
            path=path,
            name=name,
            other_attributes=other_attributes
        )


create_post("new_contact", SpecData, new_contact, router_sucker)
