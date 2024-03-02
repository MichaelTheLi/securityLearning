import json
from base64 import b64decode

from learn.learnAES.aes import decrypt_without_verify, decrypt

if __name__ == '__main__':
    f = open('data/data.json', 'rb')
    json_input = f.read()
    b64 = json.loads(json_input)
    print(b64)
    print(b64decode(b64["header"]).decode('utf-8'))
    data = decrypt_without_verify(
        b64decode(b64["nonce"]),
        b64decode(b64["header"]),
        b64decode(b64["ciphertext"])
    )

    print(f"Decrypted original data: {data.decode('utf-8')}")

    dataTampered = decrypt_without_verify(
        b64decode(b64["nonce"]),
        b64decode(b64["header"]),
        b64decode(b64["ciphertext"].replace("4", "5"))
    )

    print(f"Decrypted tampered data: {dataTampered.decode('utf-8')}")


    dataTampered = decrypt(
        b64decode(b64["nonce"]),
        b64decode(b64["tag"]),
        b64decode(b64["header"]),
        b64decode(b64["ciphertext"].replace("4", "5"))
    )
