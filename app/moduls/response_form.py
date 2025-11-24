from pydantic import BaseModel, field_serializer
from typing import Any, Optional

from app.ds import DSDict


# Шаблон для ответов клиенту
class ResponseFrom(BaseModel):
    username: str
    successfully: bool
    answer: Optional[Any]

    @field_serializer("answer")
    def serialize_answer(self, answer, _info):
        if isinstance(answer, DSDict):
            return answer.original_dict()
        elif isinstance(answer, (list, tuple)):
            return type(answer)(self.serialize_answer(v, _info) for v in answer)
        return answer
