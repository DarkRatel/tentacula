# Чтение переменных среды
Переменные среды читаются либо из окружения, либо из config.cfg
Приоритет чтения:
1. Переменные окружения;
2. Конфигурационный файл `config.cfg`.

Переменные окружения генерируются по формуле: `TENT_<РАЗДЕЛ>_<ПЕРЕМЕННАЯ>`

# Авторизация
BASIC авторизация требует указать логин, пароль и секретный ключ, указанные в параметрах окружения. LDAP авторизация требует указать группу.

Для запроса требуется передать данные:
- `username` BASIC_USERNAME или sAMAccountName DS-пользователя
- `password` - BASIC_PASSWORD или пароль DS-пользователя
- `secret-key` - SECRET_KEY

# Пример создания сертификатов
```
# Создаём корневой сертификат (CA)
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=MyRootCA"

# Серверный сертификат
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=api_1"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

# Клиентский сертификат
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=fastapi-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
```