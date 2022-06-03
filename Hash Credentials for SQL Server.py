from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

item = input()
salt = b''
item_bytes = bytearray(item, 'utf-8')
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2 ** 14,
    r=8,
    p=1,
)
byte_array_of_hash = kdf.derive(item_bytes)
print(byte_array_of_hash)
print(base64.urlsafe_b64encode(byte_array_of_hash))