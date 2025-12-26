from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# Генерация приватного ключа
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Получение публичного ключа
public_key = private_key.public_key()

# Конвертирование приватного ключа в base64
private_key = base64.b64encode(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
).decode('utf-8')

# Конвертирование публичного ключа в base 64
public_key = base64.b64encode(
    public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
).decode('utf-8')

print('Private:', private_key)
print('Public:', public_key)
