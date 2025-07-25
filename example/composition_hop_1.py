import requests

response = requests.post(
    url='https://127.0.0.1:5001/composition',
    headers={
        "username": "root",
        "password": "root_password",
    },
    verify=False,
    json={
        'url_': 'https://api_2:5002/sucker/first',
        'headers_': {
            "username": "admin_proxy",
            "password": "Nondetectuser",
        },
        'verify_': False,
        'json_': {'data': '1'}
    },
)

response.raise_for_status()

print(response.status_code)
print(response.json())