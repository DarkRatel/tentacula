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
    account_password: str


async def set_account_password(login: str, password: str, host: str, identity: str | dict, account_password: str,
                               base: str = None, log_level: int = None):
    with DSHook(login=login, password=password, host=host, port=636, base=base, log_level=log_level) as ds:
        ds.set_account_password(
            identity=identity,
            account_password=account_password
        )


create_post(endpoint="set_account_password", func=set_account_password, access=AppConfig.SUCKERS_DS__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_ds)
