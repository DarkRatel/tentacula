from pydantic import BaseModel
from typing import Any, Optional

# Шаблон для ответов клиенту
class ResponseFrom(BaseModel):
    username: str
    successfully: bool
    answer: Optional[Any]