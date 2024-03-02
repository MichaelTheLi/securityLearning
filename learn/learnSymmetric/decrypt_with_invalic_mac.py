import json
from base64 import b64decode

from learn.learnSymmetric.aes import decrypt

if __name__ == '__main__':
    f = open('data/data.json', 'rb')
    json_input = f.read()
    b64 = json.loads(json_input)
    print(b64)
    print(b64decode(b64["header"]).decode('utf-8'))
    data = decrypt(
        b64decode(b64["nonce"]),
        b"invalid_mac",
        b64decode(b64["header"]),
        b64decode(b64["ciphertext"])
    )

    print(f"Decrypted: {data.decode('utf-8')}")
