from pydantic import BaseModel

from moduls.post_base import create_post
from systems.logging import logger
from sites.suckers import router_sucker


class specData(BaseModel):
    server: str
    auth_user: str
    auth_pass: str
    ldap_filter: str


def ds_get(server, auth_user, auth_pass, ldap_filter):
    logger.info('This Use')

    return "Text"

    # from ldap3 import Server, Connection, SUBTREE, ALL
    #
    # # Define your LDAP server details
    # LDAP_SERVER_ADDRESS = server  # e.g., 'ldap.example.com' or IP address
    # LDAP_BIND_DN = auth_user  # DN of the user to bind with
    # LDAP_PASSWORD = auth_pass
    #
    # # Define search parameters
    # LDAP_SEARCH_BASE = 'DC=contoso,DC=local'  # Base DN for your search
    # LDAP_SEARCH_FILTER = ldap_filter  # Filter to find person objects
    # LDAP_ATTRIBUTES = ['cn', 'mail', 'sAMAccountName']  # Attributes to retrieve
    #
    # status = None
    # result = None
    # response = None
    # error = None
    #
    # try:
    #     # Create a Server object
    #     server = Server(LDAP_SERVER_ADDRESS, get_info=ALL)
    #
    #     # Create a Connection object and bind to the server
    #     # auto_bind=True attempts to bind immediately upon connection creation
    #     conn = Connection(server, LDAP_BIND_DN, LDAP_PASSWORD, auto_bind=True)
    #
    #     if conn.bound:
    #         logger.info("Successfully bound to LDAP server.")
    #
    #         # Perform the search operation
    #         # SUBTREE indicates searching the base DN and all sub-containers
    #         status = conn.search(
    #             LDAP_SEARCH_BASE,
    #             LDAP_SEARCH_FILTER,
    #             search_scope=SUBTREE,
    #             attributes=LDAP_ATTRIBUTES
    #         )
    #
    #         if status:
    #             logger.info(f"Found {len(conn.entries)} entries.")
    #             for entry in conn.entries:
    #                 logger.info(f"DN: {entry.entry_dn}")
    #                 for attr in LDAP_ATTRIBUTES:
    #                     if hasattr(entry, attr):
    #                         logger.info(f"  {attr}: {getattr(entry, attr).value}")
    #
    #             result = []
    #             for entry in conn.entries:
    #                 obj = {}
    #                 for attr in LDAP_ATTRIBUTES:
    #                     obj.update({str(attr): getattr(entry, attr).value})
    #                 result += [obj]
    #
    #         else:
    #             logger.info(f"Search failed: {result}")
    #             logger.info(f"Response: {response}")
    #
    #     else:
    #         logger.info("Failed to bind to LDAP server.")
    #         logger.info(f"Error: {conn.result}")
    #
    # except Exception as e:
    #     logger.info(f"An error occurred: {e}")
    #     error = e
    #
    # finally:
    #     # Unbind and close the connection
    #     if 'conn' in locals() and conn.bound:
    #         conn.unbind()
    #         logger.info("Connection unbound.")
    #
    # return {"result": result, 'response': response, 'status': status, 'error': error}

    # return {"msg": f"test1: {identaty}"}


create_post("ds_get", specData, ds_get, router_sucker)
