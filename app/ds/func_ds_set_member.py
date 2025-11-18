import ldap

from .data import DS_ACTION_MEMBER, DataDSProperties
from .ds_dict import DSDict
from .func_ds_get import search_object, gen_filter_to_id


def ds_set_member(connect, _logger, dry_run: bool, base: str,
                  identity, members, action: DS_ACTION_MEMBER = None) -> None:
    if action == 'add':
        func = add_member
    elif action == 'remove':
        func = remove_member
    else:
        raise TypeError(f"Некорректный типа действия: {action}")

    if isinstance(identity, DSDict) and identity.get('objectClass') == 'group' and identity.get('distinguishedName'):
        pass
    else:
        identity = search_object(
            connect=connect,
            _logger=_logger,
            ldap_filter=gen_filter_to_id(identity, type_object='group'),
            search_base=base,
            properties=['distinguishedName'], # ['distinguishedName', 'member'] if action == 'remove' else ['distinguishedName'],
            type_object='group',
            only_one=True,
        )[0]

    # DN домена группы
    group_domain = base.lower()[base.lower().find('dc='):]

    if isinstance(members, str):
        members = [members]

    members_id = []
    for member in members:
        if isinstance(member, str):
            member = gen_filter_to_id(member, type_object='member', return_dict=True)

        # Если distinguishedName есть, то совпадает ли домен члена с доменом группы
        if member.get('distinguishedName') and group_domain.lower() not in member['distinguishedName'].lower():
            if member.get('objectSid') and member.get('objectClass'):
                members_id.append(f"CN={member['objectSid']},CN=ForeignSecurityPrincipals,{group_domain}")
            else:
                raise TypeError(f"Для кроссдоменного управления членством {member} требуется получить "
                                f"словарь объекта с минимальным набором атрибутов: "
                                f"distinguishedName, objectSid, objectClass")
        # Если передан хотя бы distinguishedName
        elif member.get('distinguishedName'):
            members_id.append(member['distinguishedName'])
        # В остальных случах будет попытка найти объект в DS
        else:
            s_object = search_object(
                connect=connect,
                _logger=_logger,
                ldap_filter=gen_filter_to_id(member, type_object='group'),
                search_base=base,
                properties=['distinguishedName', 'objectClass'],
                type_object='member',
                only_one=True,
            )[0]
            members_id.append(s_object['distinguishedName'])

    _logger.debug(f"{action.capitalize()} member: DN: {identity['distinguishedName']}, members: {members_id}")

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
