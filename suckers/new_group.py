from pydantic import BaseModel

from moduls.post_base import create_post
from sites.suckers import router_sucker
from ds import DSHook, DS_GROUP_SCOPE, DS_GROUP_CATEGORY


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    path: str
    name: str
    sam_account_name: str
    group_scope: DS_GROUP_SCOPE
    group_category: DS_GROUP_CATEGORY
    other_attributes: dict[str, list] = None


def new_group(login: str, password: str, host: str, path: str, name: str, sam_account_name: str,
              group_scope: DS_GROUP_SCOPE, group_category: DS_GROUP_CATEGORY, other_attributes: dict[str, list] = None,
              base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.new_group(
            path=path,
            name=name,
            sam_account_name=sam_account_name,
            group_scope=group_scope,
            group_category=group_category,
            other_attributes=other_attributes
        )


create_post("new_group", SpecData, new_group, router_sucker)
