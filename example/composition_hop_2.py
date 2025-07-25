import requests

end = {
    'url': 'http://api_3:5003/sucker/first',
    'headers': {
        "username": "root",
        "password": "root_password",
    },
    'json_': {"name": "Two hoop", "value": 2}
}

hop_2 = {
    'url': 'http://api_2:5002/composition',
    'headers': {
        "username": "root",
        "password": "root_password",
    },
    'json_': end
}

response = requests.post(
    url=f'http://127.0.0.1:5001/composition',
    headers={
        "username": "root",
        "password": "root_password",
    },
    json=hop_2,
)

response.raise_for_status()

print(response.status_code)
print(response.json())
