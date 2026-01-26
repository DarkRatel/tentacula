# Минимальные зависимости
from pydantic import BaseModel  # Функция для объявления структуры ожидаемых значений
from app.moduls.post_base import create_post  # Функция создания эндпоинта типа POST
from app.sites.suckers import router_sucker  # API для ветки щупалец
from app.systems.logging import logger  # Функция логирования


# Класс основанный на BaseModel, описывающий ожидаемые значения в запросе
class SpecData(BaseModel):
    # Например, ключи типа int
    terms_1: int
    terms_2: int


# Функция, которая будет исполнена на сервере. Требуется, чтобы она была типа async
async def addition(terms_1: int, terms_2: int):
    # Для фиксации данных в логах требуется использовать "logger"
    logger.info("Hello world!")

    # Использование переменных, тип которых, по факту, был определён ещё в BaseModel
    # Если на эндпоинт не будут переданы данные описанные в BaseModel, функция не будет исполнена

    # Если функция не заканчивается "return", ответ будет равен "None"
    return terms_1 + terms_2


# Функция создающая эндпоинт на основе имени эндпоинта, функции и ожидаемых значений
create_post(endpoint="addition", base_model=SpecData, func=addition, router=router_sucker)
