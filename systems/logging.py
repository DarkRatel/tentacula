import logging

# Глобальный логгер для всей системы
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Консольный хендлер
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s'))
logger.addHandler(console_handler)
