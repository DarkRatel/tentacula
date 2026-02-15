from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSHook, DS_TYPE_OBJECT, DS_TYPE_SCOPE


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | dict = None
    ldap_filter: str = None
    properties: str | list | tuple = None
    search_scope: DS_TYPE_SCOPE = "subtree"
    type_object: DS_TYPE_OBJECT = "object"


async def get_object(login: str, password: str, host: str, base: str = None, identity: str | dict = None,
                     ldap_filter: str = None, properties: str | list | tuple = None,
                     search_scope: DS_TYPE_SCOPE = "subtree", type_object: DS_TYPE_OBJECT = "object") -> list[DSDict]:
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        result = ds.get_object(
            identity=identity,
            ldap_filter=ldap_filter,
            properties=properties,
            search_scope=search_scope,
            type_object=type_object
        )

    return result


create_post("get_object", SpecData, get_object, router_ds)
