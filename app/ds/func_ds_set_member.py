import ldap

from .data import DS_ACTION_MEMBER, DataDSProperties
from .ds_dict import DSDict
from .func_ds_get import search_object, gen_filter_to_id


def ds_set_member(connect, _logger, dry_run: bool, base: str,
                  identity: str | DSDict, members: str | list, action: DS_ACTION_MEMBER = None) -> None:
    """
    Изменение членства в группе.

    Args:
        connect: Открытое подключение к DS
        _logger: Получение логгера для вывода логов
        dry_run: Исполнение запроса без отправки команды на изменения
        base: Область работы
        identity: Группа для изменения
        members: Члены связанные с группой для изменения
        action: Тип действия (add - добавить в группу, remove - удалить из группы)
    """

    # Определение типа группы
    if action == 'add':
        func = add_member
    elif action == 'remove':
        func = remove_member
    else:
        raise TypeError(f"Некорректный типа действия: {action}")

    ### Обработка Группы
    # Если передан объект типа группа и есть distinguishedName, переходим к следующему шагу
    if isinstance(identity, DSDict) and identity.get('objectClass') == 'group' and identity.get('distinguishedName'):
        pass
    # Иначе производится попытка найти объект типа группа
    else:
        identity = search_object(
            connect=connect,
            _logger=_logger,
            ldap_filter=gen_filter_to_id(identity, type_object='group'),
            search_base=base,
            properties=['distinguishedName'],
            type_object='group',
            only_one=True,
        )[0]

    # Из distinguishedName вычленяется часть c DC
    group_domain = identity['distinguishedName'].lower()[identity['distinguishedName'].lower().find('dc='):]

    # Если член группы передан как строка, он конвертируется в массив
    if isinstance(members, str | dict | DSDict):
        members = [members]
    members = [DSDict(member) if isinstance(member, dict) else member for member in members]

    members_id = []  # Массив для ID членов
    # Перебор массива членов для вычленения ID
    for member in members:
        # Если член это строка, то строка анализируется и возвращается в виде словаря, для корректной обработки
        if isinstance(member, str):
            member = gen_filter_to_id(member, type_object='member', return_dict=True)

        # Если distinguishedName есть и домен группы не совпадает с доменом члена
        # будет попытка управлять членом как ForeignSecurityPrincipals
        if member.get('distinguishedName') and group_domain.lower() not in member['distinguishedName'].lower():

            # Если член имеем objectSid и является пользователем
            if member.get('objectSid') and member.get('objectClass') == 'user':
                # Добавления ID члена в виде ForeignSecurityPrincipals
                members_id.append(f"CN={member['objectSid']},CN=ForeignSecurityPrincipals,{group_domain}")
            else:
                raise TypeError(f"Для кроссдоменного управления членством {member} требуется получить "
                                f"словарь пользователя с минимальным набором атрибутов: "
                                f"distinguishedName, objectSid, objectClass")

        # Если в данных члена есть distinguishedName, он выберается как ID
        elif member.get('distinguishedName'):
            members_id.append(member['distinguishedName'])

        # Иначе производится попытка поиска члена в DS
        else:
            s_object = search_object(
                connect=connect,
                _logger=_logger,
                ldap_filter=gen_filter_to_id(member, type_object='member'),
                search_base=base,
                properties=['distinguishedName', 'objectClass'],
                type_object='member',
                only_one=True,
            )[0]
            members_id.append(s_object['distinguishedName'])

    _logger.debug(f"{action.capitalize()} member: DN: {identity['distinguishedName']}, members: {members_id}")

    # Перебор ID членов для внесения правок по каждому
    for m_id in members_id:
        func(connect=connect, _logger=_logger, group=identity['distinguishedName'], member=m_id, dry_run=dry_run,
             current_members=identity.get('member', None))


def add_member(connect, _logger, group: str, member, dry_run: bool, current_members: list | None):
    _logger.info(f"Add member: DN: {group}, Operation: {ldap.MOD_ADD}, Member: {member}")
    if not dry_run:
        try:
            connect.modify_s(group, [(ldap.MOD_ADD, 'member', [member.encode("utf-8")])])
        except ldap.ALREADY_EXISTS:
            _logger.debug("Object already in group")
    else:
        _logger.warning("Enabled dry run")


def remove_member(connect, _logger, group: str, member, dry_run: bool, current_members: list | None):
    _logger.info(f"Remove member: DN: {group}, Operation: {ldap.MOD_DELETE}, Member: {member}")
    if not dry_run:
        try:
            connect.modify_s(group, [(ldap.MOD_DELETE, 'member', [member.encode("utf-8")])])
        except ldap.NO_SUCH_ATTRIBUTE:
            _logger.debug("User not found in group")
        except ldap.UNWILLING_TO_PERFORM:
            _logger.warning("UNWILLING_TO_PERFORM - Object not in group")
    else:
        _logger.warning("Enabled dry run")
