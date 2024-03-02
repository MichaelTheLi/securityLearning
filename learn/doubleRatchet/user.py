import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey


class PublicUser:
    def __init__(self, name: str, publicKey: bytes):
        self.name = name
        self.publicKey = publicKey

    @staticmethod
    def findRegistered(name):
        path = Path("storage/" + name)
        if path.exists():
            with open(path, "r") as f:
                return PublicUser(name, base64.b64decode(f.read()))
        else:
            raise Exception('User ' + name + ' not found')


class User(PublicUser):
    def __init__(self, name: str, privateKey: bytes, publicKey: bytes):
        super().__init__(name, publicKey)
        self.privateKey = privateKey
        self.dr = None

    @staticmethod
    def create(name: str):
        path = Path("private_storage/" + name + '_private.pem')
        if not path.exists():
            ratchet_priv = X448PrivateKey.generate()

            with open(path, "w") as f:
                fileData = base64.b64encode(ratchet_priv.private_bytes_raw())
                f.write(fileData.decode('utf-8'))
        else:
            with open(path, "r") as f:
                fileData = base64.b64decode(f.read())
                ratchet_priv = X448PrivateKey.from_private_bytes(fileData)

        return User(
            name,
            ratchet_priv.private_bytes_raw(),
            ratchet_priv.public_key().public_bytes_raw()
        )

    def register(self):
        path = Path("storage/" + self.name)
        f = open(path, "w")
        f.write(base64.b64encode(self.publicKey).decode('utf-8'))
        f.close()
