from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSDict, DSHook, DS_TYPE_OBJECT, DS_TYPE_SCOPE
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
    type_object: DS_TYPE_OBJECT = "object"


def get_object(login: str, password: str, host: str, base: str = None, identity: str | dict = None,
                     ldap_filter: str = None, properties: str | list | tuple = None,
                     search_scope: DS_TYPE_SCOPE = "subtree", type_object: DS_TYPE_OBJECT = "object",
                     log_level: int = None) -> list[DSDict]:
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        result = ds.get_object(
            identity=identity,
            ldap_filter=ldap_filter,
            properties=properties,
            search_scope=search_scope,
            type_object=type_object
        )

    return result


create_post(endpoint="get_object", func=get_object, access=AppConfig.SUCKERS_DS__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_ds)
