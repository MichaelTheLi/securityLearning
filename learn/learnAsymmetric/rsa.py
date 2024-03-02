import json
from base64 import b64encode, b64decode

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from learn.learnAsymmetric.users import User


class RSAMessage:
    def __init__(self, nonce: bytes, tag: bytes, ciphertext: bytes, enc_session_key: bytes):
        self.nonce = nonce
        self.tag = tag
        self.ciphertext = ciphertext
        self.enc_session_key = enc_session_key

    def __str__(self):
        msg = {
            "nonce": self.nonce,
            "tag": self.tag,
            "sessionkey": self.enc_session_key,
            "ciphertext": self.ciphertext,
        }

        s = ""
        for name in msg:
            value = b64encode(msg[name]).decode('utf-8')
            s += f"{name:<15}: {value}" + "\r\n"

        return s

    def save(self, user: str):
        msg = {
            "nonce": self.nonce,
            "tag": self.tag,
            "ciphertext": self.ciphertext,
            "sessionkey": self.enc_session_key,
        }

        jsonDict = dict()

        for name in msg:
            jsonDict[name] = b64encode(msg[name]).decode('utf-8')

        result = json.dumps(jsonDict)

        f = open('data/' + user + '/incoming_message.json', 'wb')
        f.write(result.encode('utf-8'))

    @staticmethod
    def fromFile(file: str):
        with open(file, "rb") as f:
            json_input = f.read()
            b64 = json.loads(json_input)

            return RSAMessage(
                nonce=b64decode(b64["nonce"]),
                tag=b64decode(b64["tag"]),
                ciphertext=b64decode(b64["ciphertext"]),
                enc_session_key=b64decode(b64["sessionkey"]),
            )


def encrypt(data: bytes, forUser: User) -> RSAMessage:
    recipient_key = RSA.import_key(
        forUser.getPublicKey()
    )
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return RSAMessage(
        cipher_aes.nonce,
        tag,
        ciphertext,
        enc_session_key
    )


def decrypt(msg: RSAMessage, user: User) -> bytes:
    private_key = RSA.import_key(user.getPrivateKey())

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(msg.enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, msg.nonce)
    data = cipher_aes.decrypt_and_verify(msg.ciphertext, msg.tag)
    return data
