from fastapi import HTTPException, status, Request
from pydantic import BaseModel

from systems.logging import logger


class User(BaseModel):
    username: str


def current_user(request: Request) -> User or None:
    logger.info(f"Protocol: {request.headers["x-forwarded-proto"].upper()}, "
                f"Host name: {request.headers["host"]}, "
                f"Host ip: {request.headers["x-server-ip"]}")

    subject = request.headers.get("x-client-subject")
    serial = request.headers.get("x-client-serial")

    logger.info(f"Client cert Subject: {subject}")
    logger.info(f"Client cert Serial: {serial}")
    logger.info(f"Client ip: {request.headers.get("x-forwarded-for")}")

    if not all([subject, serial]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Error client certificate")

    return subject
