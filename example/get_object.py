import httpx, ssl

ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="/app/tentacula/certs/ca.crt")
ssl_ctx.load_cert_chain(certfile="/app/tentacula/certs/client.crt", keyfile="/app/tentacula/certs/client.key")
transport = httpx.HTTPTransport(verify=ssl_ctx)
client = httpx.Client(transport=transport)

# response = client.post(
#     "https://nginx_1:5001/sucker/get_object",
#     json={
#         'login': 'api_1',
#         'password': 'Cakn2o9xcJIeio2fi3mP)@!I!',
#         'host': '192.168.0.114',
#         'port': 389,
#
#         'identity': 'CN=Administrator,CN=Users,DC=contoso,DC=local',
#         'type_object': 'user'
#     }
# )
#
# response.raise_for_status()
# print("#########################")
# j = response.json()
# print(j)
# print("----------")
# print(j['answer'])

# DSHook( ) as ds:
#     v = ds.get_object()

response = client.post(
    "https://nginx_1:5001/sucker/hello_world",
    json={
        'hello': 'world'
    }
)

response.raise_for_status()
print("#########################")
j = response.json()
print(j)
print("----------")