UAC_FLAGS = {
    'SCRIPT': 0x0001,
    'ACCOUNTDISABLE': 0x0002,
    'HOMEDIR_REQUIRED': 0x0008,
    'LOCKOUT': 0x0010,
    'PASSWD_NOTREQD': 0x0020,
    'PASSWD_CANT_CHANGE': 0x0040,
    'ENCRYPTED_TEXT_PWD_ALLOWED': 0x0080,
    'TEMP_DUPLICATE_ACCOUNT': 0x0100,
    'NORMAL_ACCOUNT': 0x0200,
    'INTERDOMAIN_TRUST_ACCOUNT': 0x0800,
    'WORKSTATION_TRUST_ACCOUNT': 0x1000,
    'SERVER_TRUST_ACCOUNT': 0x2000,
    'DONT_EXPIRE_PASSWORD': 0x10000,
    'MNS_LOGON_ACCOUNT': 0x20000,
    'SMARTCARD_REQUIRED': 0x40000,
    'TRUSTED_FOR_DELEGATION': 0x80000,
    'NOT_DELEGATED': 0x100000,
    'USE_DES_KEY_ONLY': 0x200000,
    'DONT_REQ_PREAUTH': 0x400000,
    'PASSWORD_EXPIRED': 0x800000,
    'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x1000000,
    'PARTIAL_SECRETS_ACCOUNT': 0x04000000
}

_grouptype_flags = [
    {'name': 'BUILTIN_LOCAL_GROUP', 'value': 1, 'mutex_group': 1, },  # System group
    {'name': 'ACCOUNT_GROUP', 'value': 2, 'mutex_group': 2, },  # Global
    {'name': 'RESOURCE_GROUP', 'value': 4, 'mutex_group': 2, },  # DomainLocal
    {'name': 'UNIVERSAL_GROUP', 'value': 8, 'mutex_group': 2, },  # Universal
    {'name': 'APP_BASIC', 'value': 16, 'mutex_group': 2, },
    {'name': 'APP_QUERY', 'value': 32, 'mutex_group': 2, },
    {'name': 'SECURITY_ENABLED', 'value': -2147483648, 'mutex_group': 1, },  # Security or not bite Distribution
]


def uac_to_flags(numeric: int) -> list:
    return [name for name, bit in UAC_FLAGS.items() if numeric & bit]


def convert_grouptype(request: tuple | list | int) -> int | list:
    """
    Функция для конвертации флагов групп MS AD из текстовой формы в числовую и наоборот.
    Функция написана в соответствии с описанием 'MS-ADTS 2.2.12 Group Type Flags'.
    С помощью параметра 'mutex_group' реализованы взаимоисключающие группы флагов
    (т.е., может быть установлено не более одного флага из каждой mutex_group).
    :param request: Флаг или сочетание флагов в текстовой или числовой форме
    :return:
    - если в функцию был передан флаг/сочетание флагов в текстовой форме - флаг/сочетание флагов в числовой форме;
    - если в функцию был передан флаг/сочетание флагов в числовой форме - список флагов в текстовой форме.
    """

    if isinstance(request, (list, tuple)):
        if not all(item in [flag['name'] for flag in _grouptype_flags] for item in request):
            raise ValueError('Переданы некорректные значения типов группы')
        result = [flag for flag in _grouptype_flags if flag['name'] in request]

        mutex_result = [flag['mutex_group'] for flag in result]
        if len(mutex_result) != len(set(mutex_result)):
            raise ValueError(f'Одновременная установка флагов {[entry["name"] for entry in result]} невозможна')

        return sum(flag['value'] for flag in result)
    elif isinstance(request, int):
        if request & sum(flag['value'] for flag in _grouptype_flags) != request:
            raise ValueError('Переданы некорректное числовое значение')
        result = [flag for flag in _grouptype_flags if request & flag['value'] == flag['value']]

        mutex_result = [flag['mutex_group'] for flag in result]
        if len(mutex_result) != len(set(mutex_result)):
            raise ValueError(f'Одновременная установка флагов {[entry["name"] for entry in result]} невозможна')

        return [entry["name"] for entry in result]
    else:
        raise TypeError('Данная функция принимает данные только следующих типов: list, tuple, int')


def convert_object_class(name: str = None, flags: list = None) -> str | list:
    """
    Функция двухсторонней конвертации значений атрибута "ObjectClass". Требуется использовать один из ключей,
    в зависимости от типа входных данных
    :param flags: Список флагов характеризующих тип объекта
    :param name: Короткое имя объекта
    :return: Если передано имя, возвращается список флагов. Если переданы флаги, возвращается короткое имя объекта
    """
    if not any([name, flags]):
        raise RuntimeError("Требуется передать данный через один из ключей")
    elif all([name, flags]):
        raise RuntimeError("Недопустимо использовать оба ключа")

    list_types = {
        "user": ['top', 'person', 'organizationalPerson', 'user'],
        "contact": ['top', 'person', 'organizationalPerson', 'contact'],
        "group": ['top', 'group'],
        "computer": ['top', 'person', 'organizationalPerson', 'user', 'computer'],
        "organizationalUnit": ['top', 'organizationalUnit'],
        "builtinDomain": ['top', 'builtinDomain'],
        "foreignSecurityPrincipal": ['top', 'foreignSecurityPrincipal'],
        "domainDNS": ['top', 'domain', 'domainDNS'],
        "inetOrgPerson": ['top', 'user', 'person', 'inetOrgPerson', 'organizationalPerson']
    }

    if isinstance(flags, list):
        for key, item in list_types.items():
            if sorted(flags) == sorted(item):
                return key
        return flags
    elif isinstance(name, str):
        if name.lower() in list_types:
            return list_types[name.lower()]
        raise RuntimeError("Неизвестный тип объекта. Невозможно подобрать список ключей")
    else:
        raise RuntimeError("Переданы недопустимы данные")
