import requests

from fastapi import APIRouter
from pydantic import BaseModel

from moduls.post_base import create_post
from systems.logging import logger
from sites.suckers import router_sucker

router_composition = APIRouter(prefix="/composition")


class InputData(BaseModel):
    url_: str
    headers_: dict
    json_: dict
    verify_: bool


def run(url_, headers_, json_, verify_):

    logger.info(f'URL: {url_}')

    response = requests.post(
        url=url_,
        headers=headers_,
        json=json_,
        verify=verify_
    )

    response.raise_for_status()

    return response.json()


create_post('/', InputData, func=run, router=router_composition)
