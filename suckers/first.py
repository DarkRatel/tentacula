from pydantic import BaseModel

from moduls.post_base import create_post
from systems.logging import logger
from sites.suckers import router_sucker


class specData(BaseModel):
    data: str


def test1(data):
    logger.warning('This Use')

    return {"msg": f"test1: {data}"}


create_post("first", specData, test1, router_sucker)
