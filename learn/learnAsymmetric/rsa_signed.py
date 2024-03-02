from base64 import b64encode, b64decode

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15

from learn.learnAsymmetric.rsa import RSAMessage
from learn.learnAsymmetric.users import User, PublicUser


class RSASignedMessage:
    def __init__(self, msg: RSAMessage, signature: bytes):
        self.msg = msg
        self.signature = signature

    def __str__(self):
        s = str(self.msg)
        name = 'Signature'
        value = b64encode(self.signature).decode('utf-8')
        s += f"{name:<15}: {value}" + "\r\n"
        return s

    def save(self, user: str):
        self.msg.save(user)
        f = open('data/' + user + '/incoming_message.json.signature', 'wb')
        f.write(b64encode(self.signature))

    @staticmethod
    def fromFile(file: str):
        with open(file + '.signature', "rb") as f:
            return RSASignedMessage(
                RSAMessage.fromFile(file),
                b64decode(f.read())
            )


def encryptSigned(data: bytes, fromUser: User, toUser: PublicUser) -> RSASignedMessage:
    recipient_key = RSA.import_key(
        toUser.getPublicKey()
    )
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    key = RSA.import_key(fromUser.getPrivateKey())
    h = SHA256.new(ciphertext)
    signature = pkcs1_15.new(key).sign(h)

    return RSASignedMessage(
        RSAMessage(
            cipher_aes.nonce,
            tag,
            ciphertext,
            enc_session_key
        ),
        signature
    )


def decryptSigned(msg: RSASignedMessage, fromUser: PublicUser, toUser: User) -> bytes:
    key = RSA.import_key(fromUser.getPublicKey())
    h = SHA256.new(msg.msg.ciphertext)
    pkcs1_15.new(key).verify(h, msg.signature)

    private_key = RSA.import_key(toUser.getPrivateKey())

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(msg.msg.enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, msg.msg.nonce)
    data = cipher_aes.decrypt_and_verify(msg.msg.ciphertext, msg.msg.tag)

    return data
