import requests

response = requests.get(
    url='https://localhost:5001/sucker',
    headers={
        "username": "root",
        "password": "root_password",
    },
    verify=False
)

response.raise_for_status()

print(response.status_code)
j = response.json()
[print(f"{i['methods']} - {i['path']} - {i['data']}") for i in j['data']]

# ####################################################################
#
# response = requests.post(
#     url='https://localhost:5001/sucker/first',
#     headers={
#         "username": "root",
#         "password": "root_password",
#     },
#     json={'data': '1'},
#     verify=False
# )
#
# response.raise_for_status()
#
# print(response.status_code)
# j = response.json()
# print(j)

# response = requests.post(
#     url='https://localhost:5001/sucker/new_line',
#     headers={
#         "username": "root",
#         "password": "root_password",
#     },
#     verify=False
# )
#
# response.raise_for_status()
#
# print(response.status_code)
# j = response.json()
# print(j)

# response = requests.get(
#     url='https://localhost:5001/sucker',
#     headers={
#         "username": "root",
#         "password": "root_password",
#     },
#     verify=False
# )
#
# response.raise_for_status()
#
# print(response.status_code)
# j = response.json()
# [print(f"{i['methods']} - {i['path']}") for i in j['data']]