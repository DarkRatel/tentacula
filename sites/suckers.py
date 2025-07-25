import os
import importlib
import inspect

from fastapi import APIRouter, status, Depends
from fastapi.routing import APIRoute
from fastapi.responses import Response, JSONResponse

from moduls.auth.auth_manager import current_user, User
from systems.config import AppConfig

router_sucker = APIRouter(prefix="/sucker")


@router_sucker.get("/", response_class=Response)
async def sucker_root_get(user: User = Depends(current_user)) -> JSONResponse:
    routes_info = []
    for route in router_sucker.routes:
        if isinstance(route, APIRoute):
            endpoint = route.endpoint
            signature = inspect.signature(endpoint)

            in_data = [{'annotation': str(param)} for _, param in signature.parameters.items()]

            routes_info.append({
                "path": route.path,
                "methods": list(route.methods - {"HEAD", "OPTIONS"}),
                "summary": route.summary,
                "data": in_data
            })

    return JSONResponse({"user": user.username, "data": routes_info}, status_code=status.HTTP_200_OK)


# Импорт всех дополнительных путей связанных с присосками
for filename in os.listdir(AppConfig.SUCKERS_FOLDER):
    if filename.endswith(".py") and filename != "__init__.py":
        importlib.import_module(f"{AppConfig.SUCKERS_FOLDER}.{filename[:-3]}")
