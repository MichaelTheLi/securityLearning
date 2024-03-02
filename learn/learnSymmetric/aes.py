import base64

from Crypto.Cipher import AES
from pathlib import Path

from Crypto.Random import get_random_bytes

aes_mode = AES.MODE_EAX

preshared_key: bytes = b""


def encrypt(header: bytes, data: bytes) -> (bytes, bytes, bytes):
    global preshared_key

    readKeyOrGenerateKeyIfAbsent()
    cipher = AES.new(preshared_key, aes_mode)

    cipher.update(header)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return nonce, tag, ciphertext


def decrypt(nonce: bytes, tag: bytes, header: bytes, ciphertext: bytes) -> bytes:
    global preshared_key

    readKeyOrGenerateKeyIfAbsent()
    cipher = AES.new(preshared_key, aes_mode, nonce=nonce)
    cipher.update(header)

    return cipher.decrypt_and_verify(ciphertext, tag)


def decrypt_without_verify(nonce: bytes, header: bytes, ciphertext: bytes) -> bytes:
    global preshared_key

    readKeyOrGenerateKeyIfAbsent()
    cipher = AES.new(preshared_key, aes_mode, nonce=nonce)
    cipher.update(header)

    return cipher.decrypt(ciphertext)


def readKeyOrGenerateKeyIfAbsent() -> bytes:
    global preshared_key

    if preshared_key:
        return preshared_key

    path = Path('data/presharedKey.key')
    if path.exists():
        f = open(path, 'rb')
        preshared_key = f.read()
        preshared_key = base64.b64decode(preshared_key)
        return preshared_key

    preshared_key = get_random_bytes(32)
    f = open(path, 'wb')
    f.write(base64.b64encode(preshared_key))
    return preshared_key
