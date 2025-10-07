import typing
from datetime import datetime

import ldap

from _ds_dict import DSDict
from data import DataDSLDAP, DataDSProperties
from func_read_ds import search_object, identity_to_id, ATTR_EXTEND
from ds_function import search_root_dse

DS_TYPE_OBJECT = typing.Literal["object", "user", "group", "computer", "contact"]
DS_GROUP_SCOPE = typing.Literal["DomainLocal", "Global", "Universal"]
DS_GROUP_CATEGORY = typing.Literal["Security", "Distribution"]


class DSHook:
    def __init__(self, login: str, password: str, host: str, port: int = 636, dry_run: bool = False,
                 search_base: str = None):

        self._login = login
        self._password = password
        self.search_base = search_base

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

        self._connect.protocol_version = ldap.VERSION3

    def __enter__(self):
        print(f"Run LDAP Connect: {self.connect_line}, login: {self._login}")
        self._connect.simple_bind_s(self._login, self._password)
        self._search_base = self.search_base if self.search_base else search_root_dse(connect=self._connect)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._connect.unbind_s()
        return False

    def get_object(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: int = ldap.SCOPE_SUBTREE,
            type_object: DS_TYPE_OBJECT = "object"
    ) -> list[DSDict]:

        # properties:
        # userAccountControl: Enabled, PasswordNeverExpires, AccountNotDelegated
        # groupType: GroupScope, GroupCategory
        # pwdLastSet: ChangePasswordAtLogon

        properties_shadow = []
        if properties:
            if isinstance(properties, str):
                properties = [properties]

            properties += [i for i in DataDSProperties[type_object.upper()].value
                           if i.lower() not in map(str.lower, properties)]
        else:
            properties = DataDSProperties[type_object.upper()].value

        if '*' in properties:
            if len(properties) != 1:
                raise RuntimeError("При запросе всех атрибутов может быть только один знак *")

        for attr, attr_ext in ATTR_EXTEND.items():
            if attr.lower() in map(str.lower, properties):
                continue
            for (name_ext, _) in attr_ext:
                if properties[0] == '*' or name_ext.lower() in map(str.lower, properties):
                    properties_shadow += [attr]
                    break

        if all([identity, ldap_filter]):
            raise RuntimeError("You can only use one search filter")
        elif identity:
            result = search_object(
                connect=self._connect,
                ldap_filter=identity_to_id(identity, type_object=type_object),
                search_base=self._search_base,
                search_scope=search_scope,
                properties=properties,
                properties_shadow=properties_shadow,
                type_object=type_object,
                only_one=True
            )
        elif ldap_filter:
            result = search_object(
                connect=self._connect,
                ldap_filter=ldap_filter,
                search_base=self._search_base,
                search_scope=search_scope,
                properties=properties,
                properties_shadow=properties_shadow,
                type_object=type_object
            )
        else:
            raise RuntimeError("You must use one of the filters")

        return result

    def get_user(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: int = ldap.SCOPE_SUBTREE
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="user")

    def get_group(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: int = ldap.SCOPE_SUBTREE
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="group")

    def get_computer(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: int = ldap.SCOPE_SUBTREE
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="computer")

    def get_contact(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: int = ldap.SCOPE_SUBTREE
    ) -> list[DSDict]:
        return self.get_object(identity=identity, ldap_filter=ldap_filter, properties=properties,
                               search_scope=search_scope, type_object="contact")

    def get_group_member(self, identity: str | DSDict):
        pass

    def set_object(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                   replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None):
        pass

    def set_user(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                 replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                 samaccountname: str = None, userprincipalname: str = None, enabled: bool = None,
                 password_never_expires: bool = None, account_not_delegated: bool = None,
                 change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None):
        pass

    def set_group(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                  replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                  group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None):
        pass

    def set_computer(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                     replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None):
        pass

    def set_contact(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                    replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None):
        pass

    def set_account_password(self, identity: str | DSDict, password: str):
        pass

    def set_account_unlock(self, identity: str | DSDict):
        pass

    def add_group_member(self, identity: str | DSDict, members: str | DSDict | list[str] | tuple[str] | list[DSDict]):
        pass

    def remove_group_member(self, identity: str | DSDict,
                            members: str | DSDict | list[str] | tuple[str] | list[DSDict]):
        pass

    def move_object(self, identity: str | DSDict, target_path: str):
        pass

    def rename_object(self, identity: str | DSDict, new_name: str):
        pass

    def new_user(self, path: str, name: str, samaccountname: str, password: str, userprincipalname: str = None,
                 enabled: bool = None, password_never_expires: bool = None, account_not_delegated: bool = None,
                 change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None,
                 other_attributes: dict[str, list] = None):
        pass

    def new_group(self, path: str, name: str, group_scope: DS_GROUP_SCOPE, group_category: DS_GROUP_CATEGORY,
                  other_attributes: dict[str, list] = None):
        pass

    def new_contact(self, path: str, name: str, other_attributes: dict[str, list] = None):
        pass

    def remove_object(self, identity: str | DSDict):
        pass

    def remove_user(self, identity: str | DSDict):
        pass

    def remove_group(self, identity: str | DSDict):
        pass

    def remove_computer(self, identity: str | DSDict):
        pass

    def remove_contact(self, identity: str | DSDict):
        pass
