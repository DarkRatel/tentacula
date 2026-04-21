from fastapi import APIRouter
from pydantic import BaseModel
import httpx, ssl

from app.systems.logging import logger
from app.moduls.post_base import create_post
from app.systems.config import AppConfig

router_composition = APIRouter()


class SpecData(BaseModel):
    url_: str
    path_: str
    json_: dict


async def composition(url_: str, path_: str, json_: dict):
    logger.info("Original URL: %s", url_)
    logger.info("Original Path: %s", path_)
    logger.info("Original Data: %s", json_)

    transport = httpx.HTTPTransport()

    if url_ in AppConfig.COMPOSITION__TRANSIT:
        transit = AppConfig.COMPOSITION__TRANSIT[url_]

        if any([transit['SSL_CA_CERTS'], transit['SSL_CERTFILE'], transit['SSL_KEYFILE']]):
            ssl_ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=transit['SSL_CA_CERTS']
            )
            ssl_ctx.load_cert_chain(
                certfile=transit['SSL_CERTFILE'],
                keyfile=transit['SSL_KEYFILE']
            )
            transport = httpx.HTTPTransport(verify=ssl_ctx)

        if 'url_' in transit:
            url_ = transit['url_']
            logger.info("Transit URL: %s", url_)

        if 'json_' in transit:
            for k, v in transit['json_'].items():
                json_[k] = v
            logger.info("Transit Data: %s", json_)

    url_ = [url_] if isinstance(url_, str) else url_

    for url in url_:
        try:
            client = httpx.Client(transport=transport)
            response = client.post(url + path_, json=json_)
            response.raise_for_status()
            data = response.json()

            if not data['error']:
                return data['details']
            else:
                logger.error(f'Error: {data["details"]}')
                raise RuntimeError("Error answer in TRANSIT")

        except httpx.ConnectError as e:
            logger.warning(f"Host {url}: {e}")

    return None


create_post(endpoint="composition", func=composition, access=AppConfig.COMPOSITION__LIST_OF_PERMITTED,
            base_model=SpecData, router=router_composition)
