from typing import Type

from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds.ds_dict import DSDict
from ds.ds_hook import DSHook, DS_TYPE_OBJECT, DS_TYPE_SCOPE


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    port: int = 636
    base: str = None

    identity: str | Type[DSDict] = None
    ldap_filter: str = None
    properties: str | list | tuple = None
    search_scope: DS_TYPE_SCOPE = "subtree"


def get_user(login: str, password: str, host: str, port: int = 636, base: str = None,
             identity: str | DSDict = None, ldap_filter: str = None, properties: str | list | tuple = None,
             search_scope: DS_TYPE_SCOPE = "subtree"):
    with DSHook(
            login=login,
            password=password,
            host=host,
            port=port,
            base=base,
    ) as ds:
        result = ds.get_user(
            identity=identity,
            ldap_filter=ldap_filter,
            properties=properties,
            search_scope=search_scope,
        )

    return result


create_post("get_user", SpecData, get_user, router_sucker)
