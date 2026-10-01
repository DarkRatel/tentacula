"""
Класс чтения и изменения объектов в каталоге DS

Классы и функции, которые рекомендуется использовать перечисленны далее
"""
from .ds_hook import DSHook
from .data import DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY, Event
from .ds_dict import DSDict

__all__ = ["DSHook", "DSDict", "DS_TYPE_SCOPE", "DS_TYPE_OBJECT", "DS_GROUP_SCOPE", "DS_GROUP_CATEGORY", "Event"]
