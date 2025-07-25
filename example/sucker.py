import requests

response = requests.post(
    url='https://localhost:5001/sucker/first',
    headers={
        "username": "root",
        "password": "root_password",
    },
    json={'data': 'a'},
    verify=False,
)

print(response.status_code)
result = response.json()
print(result)
print(f"username: {result['username']}")
print(f"status: {result['status']}")
print(f"answer: {result['answer']}")
print("LOG:")
[print('\t',i) for i in result['log']]