from pydantic import BaseModel
from typing import Any, Optional

class ResponseFrom(BaseModel):
    username: str
    status: str
    answer: Optional[Any]
    log: list