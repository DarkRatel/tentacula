from typing import Type

from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSDict, DSHook, DS_TYPE_SCOPE


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | Type[DSDict] = None
    ldap_filter: str = None
    properties: str | list | tuple = None
    search_scope: DS_TYPE_SCOPE = "subtree"


def get_contact(login: str, password: str, host: str, base: str = None, identity: str | DSDict = None,
                ldap_filter: str = None, properties: str | list | tuple = None,
                search_scope: DS_TYPE_SCOPE = "subtree"):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        result = ds.get_contact(
            identity=identity,
            ldap_filter=ldap_filter,
            properties=properties,
            search_scope=search_scope,
        )

    return result


create_post("get_contact", SpecData, get_contact, router_ds)
