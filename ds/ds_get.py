from ds.ds_hook import DSHook, DSDict

with DSHook(login='api_1', password='Cakn2o9xcJIeio2fi3mP)@!I!', host='192.168.0.114', port=389, ) as ds:
    v = ds.get_object(identity='CN=Administrator,CN=Users,DC=contoso,DC=local', type_object='user')
    print('Result:')
    [print({k: v}) for k, v in v[0].items()]

    ds.new_contact(other_attributes={'': ['s']}, path='', name='')

    # v = ds.get_user(identity='api_1', properties=None)
    # print('Result:')
    # [print(i) for i in v]
    # print('-----')
    # [print({k: v}) for k, v in v[0].items()]
    # print('Enabled:', v[0]['Enabled'])
    # print('ENABLED:', v[0]['ENABLED'])
    # print('enabled:', v[0]['enabled'])
    # print('enABLed:', v[0]['enABLed'])
    # print('ZZZZZZZ:', v[0].get('ZZZZZZZ'))
    # print('ZZZZZZZ:', v[0]['ZZZZZZZ'])

    # v = ds.get_user(ldap_filter='(objectclass=*)', properties=None)
    # print('Result:')
    # # [print({k: v}) for k, v in v[0].items()]
    # [print(i) for i in v]
    # print(len(v))

    # v = ds.get_user(identity='administrator', properties='*')
    # print('Result:')
    # [print({k: v}) for k, v in v[0].items()]
    # print(len(v))

    #
    #
    # v = ds.get_group(identity='Many User', properties='member')
    # print('Result:')
    # # [print({k: v}) for k, v in v[0].items()]
    # [print(i) for i in v]
    # print(len(v))
    #
    #
    # v = ds.get_user(identity='user-slash', properties='memberOf')
    # print('Result:')
    # # [print({k: v}) for k, v in v[0].items()]
    # [print(i) for i in v]
    # print(len(v))
