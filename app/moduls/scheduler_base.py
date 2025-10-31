from typing import Callable


class TaskScheduler:
    def __init__(self, id_name: str, minutes: int, func: Callable):
        self.id_name = id_name
        self.minutes = minutes
        self.func = func
