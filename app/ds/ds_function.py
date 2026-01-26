import ldap


def search_root_dse(connect, _logger):
    base = ""
    search_scope = ldap.SCOPE_BASE
    ldap_filter = "(objectClass=*)"
    properties = ["namingContexts"]

    _logger.debug(f"Get dn: search_base: {base}, search_scope: {search_scope}, "
                  f"ldap_filter: {ldap_filter}, properties: {properties}")

    res = connect.search_s(base, search_scope, ldap_filter, properties)
    naming_contexts = [nc.decode() for nc in res[0][1]["namingContexts"]]

    return [nc for nc in naming_contexts if nc.lower().startswith("dc=")][0]


def search_attribute_range(connect, dn, attribute, _logger):
    all_range = []

    attr_name = attribute.split(";")[0]
    step = 1499  # Размер шага (шаг не может превышать размер правил DS)
    start = int(attribute.split(';range=')[1].split('-')[1]) + 1  # От кого числа в массиве начинается
    end = start + step  # До кого числа возвращаться

    search_base = ldap.SCOPE_SUBTREE
    ldap_filter = "(objectClass=*)"

    while True:
        attribute = f"{attr_name};range={start}-{end}"

        _logger.debug(f"Get range: search_base: {search_base}, search_scope: {dn}, "
                      f"ldap_filter: {ldap_filter}, properties: {[attribute]}")

        res = connect.search_s(dn, search_base, ldap_filter, [attribute])[0][1]

        am = [i for i in res.keys() if f'{attr_name};range=' in i][0]

        if res[am]:
            all_range += res[am]
        else:
            break

        start, end = am.split(';range=')[1].split('-')

        if '*' in end:
            break
        else:
            start = int(end) + 1
            end = int(end) + step + 1

    return all_range
