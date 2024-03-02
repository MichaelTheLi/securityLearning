import os
from pathlib import Path

from Crypto.PublicKey import RSA


class User:
    def __init__(self, key):
        self._key = key

    def getPublicKey(self) -> str:
        return self._key.publickey().export_key()

    def getPrivateKey(self) -> str:
        return self._key.export_key()


class PublicUser:
    def __init__(self, key):
        self._key = key

    def getPublicKey(self) -> str:
        return self._key.export_key()


def prepareUsers():
    getUser('user1', 'user1_passphrase')
    getUser('user2', 'user2_passphrase')

def getPublicUser(name: str) -> PublicUser:
    path = Path('data/public/' + name + '.pem')
    encoded_key = open(path, "rb").read()
    key = RSA.import_key(encoded_key)

    return PublicUser(
        key
    )


def getUser(name: str, passphrase: str) -> User:
    path = Path('data/' + name + '/private.pem')
    if not path.exists():
        return generateUser(name, passphrase)
    encoded_key = open(path, "rb").read()
    key = RSA.import_key(encoded_key, passphrase=passphrase)

    return User(
        key
    )


def generateUser(name: str, passphrase: str) -> User:
    key = RSA.generate(2048)
    encrypted_key = key.export_key(
        passphrase=passphrase,
        pkcs=8,
        protection="scryptAndAES128-CBC",
        prot_params={'iteration_count': 131072}
    )

    path = Path('data/' + name + '/private.pem')
    if not os.path.exists('data/' + name):
        os.makedirs('data/' + name)
    f = open(path, "wb")
    f.write(encrypted_key)

    path = Path('data/public/' + name + '.pem')
    if not os.path.exists('data/public'):
        os.makedirs('data/public')
    f = open(path, "wb")
    f.write(key.publickey().export_key())

    return User(
        key
    )
