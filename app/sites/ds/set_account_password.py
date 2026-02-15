from pydantic import BaseModel

from app.moduls.post_base import create_post
from . import router_ds
from app.ds import DSHook


class SpecData(BaseModel):
    login: str
    password: str
    host: str
    base: str = None

    identity: str | dict
    account_password: str


async def set_account_password(login: str, password: str, host: str, identity: str | dict, account_password: str,
                               base: str = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base) as ds:
        ds.set_account_password(
            identity=identity,
            account_password=account_password
        )


create_post("set_account_password", SpecData, set_account_password, router_ds)
