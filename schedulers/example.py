import uuid
from app.systems.logging import logger, s_id_ctx_var  # Функции для логирования


# Пример функции
def example():
    """Пример функции"""
    # Создание id-запуска
    s_id_ctx_var.set(str(uuid.uuid4()))

    logger.info('Hellow World!')


# Обязательно указать add_job в функцию "register_jobs(scheduler)"
def register_jobs(scheduler):
    # Добавление задачи в шедуллер
    scheduler.add_job(example, "interval", minutes=1, id="example", replace_existing=True,
                      max_instances=1, coalesce=True)
