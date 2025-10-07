import inspect

from fastapi import status, Depends
from fastapi.routing import APIRoute
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel

from moduls.auth.auth_manager import current_user, User
from moduls.response_form import ResponseFrom
from app import app


@app.get("/", response_class=Response)
async def sucker_root_get(user: User = Depends(current_user)) -> JSONResponse:
    routes_info = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            sig = inspect.signature(route.endpoint)
            params = []

            for name, param in sig.parameters.items():
                ann = param.annotation

                # Если это Pydantic-модель
                if param.name == 'data' and isinstance(ann, type) and issubclass(ann, BaseModel):
                    for field_name, field in ann.model_fields.items():
                        info = {
                            "name": str(field_name),
                            "type": str(field.annotation),
                            "required": str(field.is_required()),
                        }
                        params.append(info)

            routes_info.append({
                "path": route.path,
                "methods": list(route.methods),
                "params": params
            })

    return JSONResponse(
        ResponseFrom(username=str(user), status='ok', answer=routes_info).model_dump(),
        status_code=status.HTTP_200_OK
    )
