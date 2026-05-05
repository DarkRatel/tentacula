import inspect

from fastapi import APIRouter
from fastapi.routing import APIRoute
from pydantic import BaseModel

from app.main import app
from app.moduls.post_base import create_post
from app.systems.config import AppConfig

router_root = APIRouter()


def root():
    """Функция root подключения к Тентакуле, которая возвращает список всех опубликованных Присосок"""
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

    return routes_info


create_post(endpoint="/", func=root, access=AppConfig.SECURITY__LIST_OF_PERMITTED,
            base_model=None, router=router_root)
