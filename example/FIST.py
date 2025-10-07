import httpx, ssl

ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="/app/tentacula/certs/ca.crt")
ssl_ctx.load_cert_chain(certfile="/app/tentacula/certs/client.crt", keyfile="/app/tentacula/certs/client.key")
transport = httpx.HTTPTransport(verify=ssl_ctx)
client = httpx.Client(transport=transport)

response = client.post(
    "https://nginx_1:5001/sucker/first",
    json={
        'username': 'sco-ad',
        'password': '1234556',
        'ldap_filer': "(samaccountname=vtb1234556)"
    }
)

response.raise_for_status()
print("#########################")
j = response.json()
print(j)
