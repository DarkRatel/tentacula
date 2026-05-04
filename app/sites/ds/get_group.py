from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSDict, DSHook, DS_TYPE_SCOPE
from app.systems.config import AppConfig


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None
    log_level: int = None

    identity: str | dict = None
    ldap_filter: str = None
    properties: str | list | tuple = None
    search_scope: DS_TYPE_SCOPE = "subtree"


def get_group(login: str, password: str, host: str, base: str = None, identity: str | dict = None,
                    ldap_filter: str = None, properties: str | list | tuple = None,
                    search_scope: DS_TYPE_SCOPE = "subtree", log_level: int = None) -> list[DSDict]:
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        result = ds.get_group(
            identity=identity,
            ldap_filter=ldap_filter,
            properties=properties,
            search_scope=search_scope,
        )

    return result


create_post(endpoint="get_group", func=get_group, access=AppConfig.SUCKERS_DS__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_ds)
