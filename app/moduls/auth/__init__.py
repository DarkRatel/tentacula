"""
Определяется функция, которая будет использоваться для проверки клиента на эндпоинте
"""
from app.systems.config import AppConfig

__all__ = ["get_current_user"]

if AppConfig.SECURITY__AUTHENTICATION_TYPE == 'CERTIFICATE':
    from .auth_get_cert import permission_user

    get_current_user = permission_user
elif AppConfig.SECURITY__AUTHENTICATION_TYPE == 'NONE':
    from .auth_get_none import permission_user

    get_current_user = permission_user
elif AppConfig.SECURITY__AUTHENTICATION_TYPE == 'LDAP_MEMBERS':
    from .auth_get_ldap_members import permission_user

    get_current_user = permission_user
else:
    raise ValueError(f'Unsupported AUTHENTICATION_TYPE: {AppConfig.SECURITY__AUTHENTICATION_TYPE}')
