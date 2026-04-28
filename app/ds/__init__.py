"""
Класс чтения и изменения объектов в каталоге DS

Классы и функции, которые рекомендуется использовать перечисленны далее
"""

from .ds_hook import DSHook, DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY
from .ds_dict import DSDict

__all__ = ["DSHook", "DSDict", "DS_TYPE_SCOPE", "DS_TYPE_OBJECT", "DS_GROUP_SCOPE", "DS_GROUP_CATEGORY"]
