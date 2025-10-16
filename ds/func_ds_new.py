import ldap


def remove():
    (ldap.MOD_DELETE, 'attr', [''])


def add():
    return (ldap.MOD_ADD, 'attr', [''])


def replace():
    (ldap.MOD_REPLACE, 'attr', [''])


def clear():
    return (ldap.MOD_DELETE, 'attr', None)








def query_ds():
    _connect.add_s('DN', list[tuple])
    _connect.modify_s('DN', list[tuple])
