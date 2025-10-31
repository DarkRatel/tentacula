from fastapi import APIRouter
from pydantic import BaseModel
import httpx, ssl

from app.moduls.post_base import create_post
from app.systems.logging import logger
from app.config import AppConfig

router_composition = APIRouter(prefix="/composition")


class InputData(BaseModel):
    url_: str
    json_: dict


def run(url_, json_):
    logger.info(f'URL: {url_}')

    if url_ not in AppConfig.TRANSIT:
        raise RuntimeError(f"Not find rule {url_} in TRANSIT")

    new_path = AppConfig.TRANSIT[url_]

    # if new_path['hop']:
    #     new_path =

    url_ = new_path['address']
    logger.info(f"End address query: {url_}")

    ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=new_path['SSL_CA_CERTS'])
    ssl_ctx.load_cert_chain(certfile=new_path['SSL_CERTFILE'], keyfile=new_path['SSL_KEYFILE'])
    transport = httpx.HTTPTransport(verify=ssl_ctx)
    client = httpx.Client(transport=transport)

    response = client.post(
        url_,
        json=json_
    )

    response.raise_for_status()

    data = response.json()

    if data['status'] == 'ok':
        return data['answer']
    else:
        raise RuntimeError("Error answer in TRANSIT")


create_post('/', InputData, func=run, router=router_composition)
