from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSDict, DSHook, DS_TYPE_OBJECT, DS_TYPE_SCOPE
from app.systems.config import AppConfig


class SpecData(BaseModel):
    login: str
    password: str
    host: str | list[str]
    base: str = None
    log_level: int = None

    ldap_filter: str = '(objectClass=*)'
    properties: str | list | tuple = '*'


def get_root_dse(login: str, password: str, host: str | list[str], base: str = None, log_level: int = None,
                 ldap_filter: str = '(objectClass=*)', properties: str | list | tuple = '*') -> list[DSDict]:
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        result = ds.get_root_dse(
            ldap_filter=ldap_filter,
            properties=properties,
        )

    return result


create_post(endpoint="get_root_dse", func=get_root_dse, access=AppConfig.SUCKERS_DS__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_ds)
