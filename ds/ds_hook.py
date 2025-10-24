from datetime import datetime

import ldap

from .ds_dict import DSDict
from .data import DataDSProperties, DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY
from .func_ds_get import search_object, gen_filter_to_id
from .ds_function import search_root_dse
from .convertors_value import UAC_FLAGS
from .func_general import gen_uac, gen_gt, gen_change_pwd_at_logon, gen_account_exp_date
from .func_ds_new import ds_new
from .func_ds_set import ds_set
from .func_ds_set_member import ds_set_member


class DSHook:
    def __init__(self, login: str, password: str, host: str, port: int = 636, base: str = None,
                 dry_run: bool = False):

        self._login = login
        self._password = password
        self.base = base

        if port == 636:
            prefix = 'ldaps'
        elif port == 389:
            prefix = 'ldap'
        else:
            raise RuntimeError(f"Only 636 or 389 ports are allowed")

        self.connect_line = f"{prefix}://{host}:{port}"

        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        self._connect = ldap.initialize(self.connect_line)

        self._connect.set_option(ldap.OPT_REFERRALS, 0)
        self._connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        self._connect.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        self._connect.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

        self._connect.protocol_version = ldap.VERSION3

    def __enter__(self):
        print(f"Run LDAP Connect: {self.connect_line}, login: {self._login}")
        self._connect.simple_bind_s(self._login, self._password)
        self.base = self.base if self.base else search_root_dse(connect=self._connect)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._connect.unbind_s()
        return False

    def get_object(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree",
            type_object: DS_TYPE_OBJECT = "object"
    ) -> list[DSDict]:

        # properties:
        # userAccountControl: Enabled, PasswordNeverExpires, AccountNotDelegated
        # groupType: GroupScope, GroupCategory
        # pwdLastSet: ChangePasswordAtLogon

        if properties:
            if isinstance(properties, str):
                properties = [properties]

            if '*' in properties:
                if len(properties) != 1:
                    raise RuntimeError("При запросе всех атрибутов может быть только один знак *")
            else:
                properties = list(set([i.casefold() for i in properties]))
                properties += [i.casefold() for i in DataDSProperties[type_object.upper()].value
                               if i.casefold() not in properties]

        else:
            properties = list(set([i.casefold() for i in DataDSProperties[type_object.upper()].value]))

        if all([identity, ldap_filter]):
            raise RuntimeError("You can only use one search filter")
        elif identity:
            result = search_object(
                connect=self._connect,
                ldap_filter=gen_filter_to_id(identity, type_object=type_object),
                search_base=self.base,
                search_scope=search_scope,
                properties=properties,
                type_object=type_object,
                only_one=True
            )
        elif ldap_filter:
            result = search_object(
                connect=self._connect,
                ldap_filter=ldap_filter,
                search_base=self.base,
                search_scope=search_scope,
                properties=properties,
                type_object=type_object
            )
        else:
            raise RuntimeError("You must use one of the filters")

        return result

    def get_user(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="user")

    def get_group(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="group")

    def get_computer(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="computer")

    def get_contact(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="contact")

    def get_group_member(self, identity: str | DSDict) -> list[DSDict]:
        result = search_object(
            connect=self._connect,
            ldap_filter=gen_filter_to_id(identity, type_object='group'),
            search_base=self.base,
            properties=None,
            type_object='group',
            only_one=True
        )[0]

        return search_object(
            connect=self._connect,
            ldap_filter=f"(memberOf={result['distinguishedName']})",
            search_base=self.base,
            properties=DataDSProperties['MEMBER'].value,
            type_object='object',
            only_one=False
        )

    def set_object(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                   replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                   description: str = None) -> None:
        """
        Последовательность исполнений: remove, add, replace, clear
        :param remove: Удалить одно из значений в атрибуте.
        :param add: Добавить значение в атрибут.
        :param replace: Полная замена всех значений.
        :param clear: Очистка в атрибуте.
        """

        special = DSDict({
            'displayName': display_name,
            'description': description
        })

        ds_set(connect=self._connect, type_object="object", identity=identity, base=self.base,
               remove=remove, add=add, replace=replace, clear=clear, special=special)

    def set_user(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                 replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                 description: str = None, sam_account_name: str = None, user_principal_name: str = None,
                 enabled: bool = None, password_never_expires: bool = None, account_not_delegated: bool = None,
                 change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None) -> None:
        if user_principal_name and '@' not in user_principal_name:
            raise RuntimeError("В userprincipalname домен должен быть указан через @")

        special = DSDict()

        if display_name: special.update({'displayName': display_name})
        if description: special.update({'description': description})
        if sam_account_name: special.update({'sAMAccountName': sam_account_name})
        if user_principal_name: special.update({'userPrincipalName': user_principal_name})
        if account_expiration_date is not None: special.update({'accountExpires': account_expiration_date})
        if change_password_at_logon is not None: special.update({'pwdLastSet': change_password_at_logon})

        if [True for i in [enabled, password_never_expires, account_not_delegated] if i is not None]:
            special['userAccountControl'] = DSDict()

            if enabled is not None: special['userAccountControl']['Enabled'] = enabled
            if password_never_expires is not None:
                special['userAccountControl']['PasswordNeverExpires'] = password_never_expires
            if account_not_delegated is not None:
                special['userAccountControl']['AccountNotDelegated'] = account_not_delegated

        ds_set(connect=self._connect, type_object="user", identity=identity, base=self.base,
               remove=remove, add=add, replace=replace, clear=clear, special=special)

    def set_group(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                  replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                  description: str = None, sam_account_name: str = None,
                  group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None) -> None:

        special = DSDict()

        if display_name: special.update({'displayName': display_name})
        if description: special.update({'description': description})
        if sam_account_name: special.update({'sAMAccountName': sam_account_name})

        if [True for i in [group_scope, group_category] if i is not None]:
            special['groupType'] = DSDict()

            if group_scope is not None: special['groupType']['GroupScope'] = group_scope
            if group_category is not None: special['groupType']['GroupCategory'] = group_category

        ds_set(connect=self._connect, type_object="group", identity=identity, base=self.base,
               remove=remove, add=add, replace=replace, clear=clear, special=special)

    def set_computer(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                     replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                     description: str = None) -> None:
        special = DSDict({
            'displayName': display_name,
            'description': description,
        })

        ds_set(connect=self._connect, type_object="computer", identity=identity, base=self.base,
               remove=remove, add=add, replace=replace, clear=clear, special=special)

    def set_contact(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                    replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                    description: str = None) -> None:
        special = DSDict({
            'displayName': display_name,
            'description': description,
        })

        ds_set(connect=self._connect, type_object="contact", identity=identity, base=self.base,
               remove=remove, add=add, replace=replace, clear=clear, special=special)

    def set_account_password(self, identity: str | DSDict, account_password: str) -> None:
        ds_set(connect=self._connect, type_object="user", identity=identity, base=self.base,
               replace={'unicodePwd': [account_password]})

    def set_account_unlock(self, identity: str | DSDict) -> None:
        ds_set(connect=self._connect, type_object="user", identity=identity, base=self.base,
               replace={'lockoutTime': ["0"]})

    def add_group_member(self, identity: str | DSDict,
                         members: str | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        ds_set_member(connect=self._connect, identity=identity, base=self.base, members=members, action='add')

    def remove_group_member(self, identity: str | DSDict,
                            members: str | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        ds_set_member(connect=self._connect, identity=identity, base=self.base, members=members, action='remove')

    def move_object(self, identity: str | DSDict, target_path: str) -> None:
        result = search_object(
            connect=self._connect,
            ldap_filter=gen_filter_to_id(identity, type_object='object'),
            search_base=self.base,
            properties=['cn', 'distinguishedName'],
            type_object='object',
            only_one=True,
        )[0]

        print(f"Move object: DN: {result['distinguishedName']}, new path: {target_path}")

        self._connect.rename_s(result['distinguishedName'],
                               ldap.dn.explode_dn(result['distinguishedName'])[0], target_path)

    def rename_object(self, identity: str | DSDict, new_name: str) -> None:
        result = search_object(
            connect=self._connect,
            ldap_filter=gen_filter_to_id(identity, type_object='object'),
            search_base=self.base,
            properties=['cn', 'name', 'distinguishedName'],
            type_object='object',
            only_one=True,
        )[0]

        print(f"Rename object: DN: {result['distinguishedName']}, new name: {new_name}, "
              f"old name: {result['name']}, "
              f"old cn: {result['cn']}")

        self._connect.rename_s(result['distinguishedName'], f"CN={new_name}")

    def new_user(self, path: str, name: str, sam_account_name: str, account_password: str, display_name: str = None,
                 user_principal_name: str = None, enabled: bool = None, password_never_expires: bool = None,
                 account_not_delegated: bool = None, change_password_at_logon: bool = None,
                 account_expiration_date: bool | datetime = None, other_attributes: dict[str, list] = None) -> None:

        dict_object = DSDict()

        dict_object['userAccountControl'] = [str(gen_uac(
            uac=UAC_FLAGS['NORMAL_ACCOUNT'],
            enabled=enabled,
            password_never_expires=password_never_expires,
            account_not_delegated=account_not_delegated,
            password_not_required=False,
        ))]

        if change_password_at_logon is not None:
            dict_object['pwdLastSet'] = [gen_change_pwd_at_logon(change_password_at_logon)]

        if account_expiration_date is not None:
            dict_object['accountExpires'] = [gen_account_exp_date(account_expiration_date)]

        if user_principal_name:
            dict_object['userPrincipalName'] = [user_principal_name]

        dict_object['unicodePwd'] = [account_password]

        dict_object['sAMAccountName'] = [sam_account_name]

        ds_new(connect=self._connect, type_object='user', path=path, name=name, display_name=display_name,
               extend=dict_object, other_attributes=other_attributes)

    def new_group(self, path: str, name: str, sam_account_name: str,  display_name: str = None, group_scope: DS_GROUP_SCOPE = 'Global',                  group_category: DS_GROUP_CATEGORY = 'Security', other_attributes: dict[str, list] = None) -> None:
        dict_object = DSDict()

        dict_object['sAMAccountName'] = [sam_account_name]
        dict_object['groupType'] = [str(gen_gt(gt=0, group_scope=group_scope, group_category=group_category))]

        ds_new(connect=self._connect, type_object='group', path=path, name=name, display_name=display_name,
               extend=dict_object, other_attributes=other_attributes)

    def new_contact(self, path: str, name: str, display_name: str = None,
                    other_attributes: dict[str, list] = None) -> None:
        ds_new(connect=self._connect, type_object='contact', path=path, name=name, display_name=display_name,
               extend=None, other_attributes=other_attributes)

    def remove_object(self, identity: str | DSDict, type_object: DS_TYPE_OBJECT = "object") -> None:
        result = search_object(
            connect=self._connect,
            ldap_filter=gen_filter_to_id(identity, type_object=type_object),
            search_base=self.base,
            properties=['distinguishedName'],
            type_object=type_object,
            only_one=True,
        )[0]

        print(f"Remove object: DN: {result['distinguishedName']}")

        self._connect.delete_s(result['distinguishedName'])

    def remove_user(self, identity: str | DSDict) -> None:
        self.remove_object(identity=identity, type_object="user")

    def remove_group(self, identity: str | DSDict) -> None:
        self.remove_object(identity=identity, type_object="group")

    def remove_computer(self, identity: str | DSDict) -> None:
        self.remove_object(identity=identity, type_object="computer")

    def remove_contact(self, identity: str | DSDict) -> None:
        self.remove_object(identity=identity, type_object="contact")
