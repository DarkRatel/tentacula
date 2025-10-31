import typing

import ldap

from .ds_dict import DSDict
from .data import DS_ACTION_MEMBER, DataDSProperties

from .func_ds_get import search_object, gen_filter_to_id


def ds_set_member(connect, _logger, base: str, identity, members, action: DS_ACTION_MEMBER = None, ) -> None:
    if action == 'add':
        a_code = ldap.MOD_ADD
    elif action == 'remove':
        a_code = ldap.MOD_DELETE
    else:
        raise TypeError(f"Некорректный типа действия: {action}")

    result = search_object(
        connect=connect,
        ldap_filter=gen_filter_to_id(identity, type_object='group'),
        search_base=base,
        properties=['member', 'distinguishedName'] if action == 'remove' else ['distinguishedName'],
        type_object='group',
        only_one=True,
    )[0]

    domain = base.lower()[base.lower().find('dc='):]

    if isinstance(members, str):
        members = [members]

    members_id = []
    for member in members:
        member = gen_filter_to_id(member, type_object='member', return_dict=True)
        member['objectClass'] = 'member'

        if not all([member.get('objectClass'), member.get('distinguishedName')]):
            member = search_object(
                connect=connect,
                ldap_filter=gen_filter_to_id(member, type_object='member'),
                search_base=base,
                properties=DataDSProperties['member'.upper()].value,
                type_object='member',
                only_one=True,
            )[0]

        members_id += [f'<SID={member['objectSid']}>']

    members_id = [(a_code, 'member', [f'{v}'.encode("utf-8") for v in members_id])]

    _logger.info(f"{action.capitalize()} member: DN: {result['distinguishedName']}, members: {members_id}")
    connect.modify_s(result['distinguishedName'], members_id)
