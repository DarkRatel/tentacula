from pydantic import BaseModel
from typing import Any, Optional

class ResponseFrom(BaseModel):
    username: str
    successfully: bool
    answer: Optional[Any]