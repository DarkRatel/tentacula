import json
import httpx, ssl
from datetime import datetime

from app.ds import DSHook
from app.ds import DSDict
from app.ds import DS_TYPE_SCOPE, DS_TYPE_OBJECT, DS_GROUP_SCOPE, DS_GROUP_CATEGORY


# Напрямую к AD: логин пароль
# Через Тентаклю
# Через Airflow:

def datetime_parser(dct):
    for k, v in dct.items():
        if isinstance(v, list):
            if isinstance(v, str):
                try:
                    dct[k] = datetime.fromisoformat(v)
                except ValueError:
                    pass
        if isinstance(v, str):
            try:
                dct[k] = datetime.fromisoformat(v)
            except ValueError:
                pass
    return dct


class SDSHook:
    def __init__(self, login: str, password: str, host: str, base: str = None, dry_run: bool = False,
                 cafile: str = None, certfile: str = None, keyfile: str = None,
                 airflow_conn_id: str = None) -> None:
        self._dry_run = dry_run

        if airflow_conn_id:
            from airflow.hooks.base_hook import BaseHook

            _config = BaseHook.get_connection(airflow_conn_id)

            self._login = _config.login
            self._password = _config.password
            self._host = _config.host
            self._base = _config.schema

            _data = json.loads(_config.get_extra())
            self._cafile = _config.get('cafile')
            self._certfile = _config.get('certfile')
            self._keyfile = _config.get('keyfile')
        else:
            self._login = login
            self._password = password
            self._host = host
            self._base = base

            self._cafile = cafile
            self._certfile = certfile
            self._keyfile = keyfile

        self.tentacula = True if 'http' in self._host.lower() else False

        if 'http' in self._host.lower():
            self.tentacula = True

            index_split = self._host[::-1].index('/')
            self._host = self._host[:-index_split]

            self._json_auth = {
                'login': self._login,
                'password': self._password,
                'host': self._host[-index_split:],
                'base': self._base
            }

        if all([cafile, certfile, keyfile]):
            ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
            ssl_ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
            transport = httpx.HTTPTransport(verify=ssl_ctx)
            self.client = httpx.Client(transport=transport)

    def get_object(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree",
            type_object: DS_TYPE_OBJECT = "object"
    ) -> list[DSDict]:
        args = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                  'search_scope': search_scope, 'type_object': type_object}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/get_object",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def get_user(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        args = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                  'search_scope': search_scope}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/get_user",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def get_group(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        args = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                  'search_scope': search_scope}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/get_group",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def get_computer(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        args = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                  'search_scope': search_scope}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/get_computer",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def get_contact(
            self, identity: str | DSDict = None, ldap_filter: str = None,
            properties: str | list | tuple = None, search_scope: DS_TYPE_SCOPE = "subtree"
    ) -> list[DSDict]:
        args = {k: v for k, v in {'identity': identity, 'ldap_filter': ldap_filter, 'properties': properties,
                                  'search_scope': search_scope}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/get_contact",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def get_group_member(self, identity: str | DSDict) -> list[DSDict]:
        args = {k: v for k, v in {'identity': identity}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/get_group_member",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def set_object(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                   replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                   description: str = None) -> None:
        args = {k: v for k, v in {'identity': identity, 'remove': remove, 'add': add,
                                  'replace': replace, 'clear': clear, 'display_name': display_name,
                                  'description': description}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/set_object",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def set_user(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                 replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                 description: str = None, sam_account_name: str = None, user_principal_name: str = None,
                 enabled: bool = None, password_never_expires: bool = None, account_not_delegated: bool = None,
                 change_password_at_logon: bool = None, account_expiration_date: bool | datetime = None) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                 'display_name': display_name, 'description': description, 'sam_account_name': sam_account_name,
                 'user_principal_name': user_principal_name, 'enabled': enabled,
                 'password_never_expires': password_never_expires, account_not_delegated: account_not_delegated,
                 'change_password_at_logon': change_password_at_logon,
                 'account_expiration_date': account_expiration_date}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/set_user",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def set_group(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                  replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                  description: str = None, sam_account_name: str = None,
                  group_scope: DS_GROUP_SCOPE = None, group_category: DS_GROUP_CATEGORY = None) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                 'display_name': display_name, 'description': description, 'sam_account_name': sam_account_name,
                 'group_scope': group_scope, 'group_category': group_category}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/set_group",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def set_computer(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                     replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                     description: str = None) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                 'display_name': display_name, 'description': description}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/set_computer",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def set_contact(self, identity: str | DSDict, remove: dict = None, add: dict[str, list] = None,
                    replace: dict[str, list] = None, clear: list[str] = None, display_name: str = None,
                    description: str = None) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'remove': remove, 'add': add, 'replace': replace, 'clear': clear,
                 'display_name': display_name, 'description': description}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/set_contact",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def set_account_password(self, identity: str | DSDict, account_password: str) -> None:
        args = {k: v for k, v in
                {'identity': identity}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/set_account_password",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def set_account_unlock(self, identity: str | DSDict) -> None:
        args = {k: v for k, v in
                {'identity': identity}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/set_account_unlock",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def add_group_member(self, identity: str | DSDict,
                         members: str | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'members': members}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/add_group_member",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def remove_group_member(self, identity: str | DSDict,
                            members: str | DSDict | list[str] | tuple[str] | list[DSDict]) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'members': members}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/remove_group_member",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def move_object(self, identity: str | DSDict, target_path: str) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'target_path': target_path}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/move_object",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def rename_object(self, identity: str | DSDict, new_name: str) -> None:
        args = {k: v for k, v in
                {'identity': identity, 'new_name': new_name}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/rename_object",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def new_user(self, path: str, name: str, sam_account_name: str, account_password: str, display_name: str = None,
                 user_principal_name: str = None, enabled: bool = None, password_never_expires: bool = None,
                 account_not_delegated: bool = None, change_password_at_logon: bool = None,
                 account_expiration_date: bool | datetime = None, other_attributes: dict[str, list] = None) -> None:
        args = {k: v for k, v in
                {'path': path, 'name': name, 'sam_account_name': sam_account_name, 'account_password': account_password,
                 'display_name': display_name, 'user_principal_name': user_principal_name, 'enabled': enabled,
                 'password_never_expires': password_never_expires, 'account_not_delegated': account_not_delegated,
                 'change_password_at_logon': change_password_at_logon,
                 'account_expiration_date': account_expiration_date, 'other_attributes': other_attributes}.items() if
                v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/new_user",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def new_group(self, path: str, name: str, sam_account_name: str, display_name: str = None,
                  group_scope: DS_GROUP_SCOPE = 'Global', group_category: DS_GROUP_CATEGORY = 'Security',
                  other_attributes: dict[str, list] = None) -> None:
        args = {k: v for k, v in
                {'path': path, 'name': name, 'sam_account_name': sam_account_name,
                 'display_name': display_name, 'other_attributes': other_attributes, 'group_scope': group_scope,
                 'group_category': group_category}.items() if
                v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/new_group",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def new_contact(self, path: str, name: str, display_name: str = None,
                    other_attributes: dict[str, list] = None) -> None:
        args = {k: v for k, v in
                {'path': path, 'name': name, 'display_name': display_name,
                 'other_attributes': other_attributes}.items() if
                v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/new_contact",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def remove_object(self, identity: str | DSDict, type_object: DS_TYPE_OBJECT = "object") -> None:
        args = {k: v for k, v in {'identity': identity, 'type_object': type_object}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/remove_object",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def remove_user(self, identity: str | DSDict) -> None:
        args = {k: v for k, v in {'identity': identity}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/remove_user",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def remove_group(self, identity: str | DSDict) -> None:
        args = {k: v for k, v in {'identity': identity}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/remove_group",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def remove_computer(self, identity: str | DSDict) -> None:
        args = {k: v for k, v in {'identity': identity}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/remove_computer",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response

    def remove_contact(self, identity: str | DSDict) -> None:
        args = {k: v for k, v in {'identity': identity}.items() if v is not None}
        response = []

        if self.tentacula:
            response = self.client.post(
                f"{self._host}sucker/remove_contact",
                json=self._json_auth.update(args),
            )
            response.raise_for_status()
            response = response.json(object_hook=datetime_parser)
        else:
            with DSHook(login=self._login, password=self._password, host=self._host, port=636, base=self._base) as ds:
                response = ds.get_object(**args)

        return response
