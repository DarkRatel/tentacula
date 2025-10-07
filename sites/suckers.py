import os
import importlib

from fastapi import APIRouter

from systems.config import AppConfig

router_sucker = APIRouter(prefix="/sucker")

# Импорт всех дополнительных путей связанных с присосками
for filename in os.listdir(AppConfig.SUCKERS_FOLDER):
    if filename.endswith(".py") and filename != "__init__.py":
        importlib.import_module(f"{AppConfig.SUCKERS_FOLDER}.{filename[:-3]}")
