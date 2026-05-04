from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSHook
from app.systems.config import AppConfig


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None
    log_level: int = None

    identity: str | dict
    remove: dict = None
    add: dict[str, list] = None
    replace: dict[str, list] = None
    clear: list[str] = None
    display_name: str = None


def set_object(login: str, password: str, host: str, identity: str | dict, base: str = None,
                     remove: dict[str, list | bool | str] = None, add: dict[str, list | bool | str] = None,
                     replace: dict[str, list | bool | str] = None, clear: list[str] = None,
                     display_name: str = None, log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        ds.set_object(
            identity=identity,
            remove=remove,
            add=add,
            replace=replace,
            clear=clear,
            display_name=display_name
        )


create_post(endpoint="set_object", func=set_object, access=AppConfig.SUCKERS_DS__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_ds)
