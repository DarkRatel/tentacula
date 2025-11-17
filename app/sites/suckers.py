import os
import importlib

from fastapi import APIRouter

from app.systems.config import AppConfig

# APIRouter для пользовательских присосок
router_sucker = APIRouter(prefix="/sucker")

# Импорт пользовательских присосок из папки
for filename in os.listdir(AppConfig.SUCKERS_FOLDER):
    if filename.endswith(".py") and filename != "__init__.py":
        module_path = os.path.join(AppConfig.SUCKERS_FOLDER, filename)
        module_name = filename[:-3]

        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # Загрузка модуля
