# Минимальные зависимости
import logging
from pydantic import BaseModel  # Функция для объявления структуры ожидаемых значений
from app.moduls.post_base import create_post  # Функция создания эндпоинта типа POST
from app.sites.suckers import router_sucker  # API для ветки Присосок

logger = logging.getLogger(__name__)


# Класс основанный на BaseModel, описывающий ожидаемые значения в запросе
# Не требуется, если не нужны входные значения
class SpecData(BaseModel):
    # Например, ключи типа int
    terms_1: int
    terms_2: int


# Функция, которая будет исполнена на сервере. Требуется функция обычного типа
def example(terms_1: int, terms_2: int):
    # Для фиксации данных в логах требуется использовать "logger"
    # и передавать переменные стандартным спецификатором %*
    logger.info("Hello world!")

    # Использование переменных, тип которых, по факту, был определён ещё в BaseModel
    # Если на эндпоинт не будут переданы данные описанные в BaseModel, функция не будет исполнена

    # Если функция не заканчивается "return", ответ будет равен "None"
    return terms_1 + terms_2


# Функция создающая эндпоинт на основе имени эндпоинта, функции и ожидаемых значений.
# Если включен держим работы проверки клиента, требуется указать в ключе access соответствующий идентификатор клиента
# Если входные данные не требуется, base_model должен быть равен None
create_post(endpoint="example", base_model=SpecData, func=example, router=router_sucker, access=[])
