import ldap

def search_root_dse(connect):
    res = connect.search_s("", ldap.SCOPE_BASE, "(objectClass=*)", ["namingContexts"])
    naming_contexts = [nc.decode() for nc in res[0][1]["namingContexts"]]

    return [nc for nc in naming_contexts if nc.lower().startswith("dc=")][0]

def search_attribute_range(connect, dn, attribute):

    all_range = []

    attr_name = attribute.split(";")[0]
    step = 1499  # Размер шага (шаг не может превышать размер правил DS)
    start = int(attribute.split(';range=')[1].split('-')[1]) + 1  # От кого числа в массиве начинается
    end = start + step  # До кого числа возвращаться

    while True:
        attribute = f"{attr_name};range={start}-{end}"

        res = connect.search_s(dn, ldap.SCOPE_BASE, "(objectClass=*)", [attribute])[0][1]

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