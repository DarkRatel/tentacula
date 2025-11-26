import inspect

from fastapi import status, Depends
from fastapi.routing import APIRoute
from fastapi.responses import Response, JSONResponse
from pydantic import BaseModel

from app.moduls.auth.auth_manager import current_user, User
from app.moduls.response_form import ResponseFrom
from app.main import app


@app.get("/", response_class=Response)
async def sucker_root_get(user: User = Depends(current_user)) -> JSONResponse:
    """Корневой сайт приложения, возвращающий все опубликованные эндпоинты"""
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

    return JSONResponse(content=routes_info, status_code=status.HTTP_200_OK)
