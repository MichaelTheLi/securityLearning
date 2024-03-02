import json
from base64 import b64encode

from learn.learnAES.aes import encrypt

if __name__ == '__main__':
    header = b"It's certainly me, trust me"
    data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam imperdiet tincidunt eros ut congue."

    print(f"Header in base64: {b64encode(header).decode('utf-8')}")
    print(f"Data in base64: {b64encode(data).decode('utf-8')}")
    print()

    nonce, tag, cipherText = encrypt(header, data)
    msg = {
        "nonce": nonce,
        "tag": tag,
        "header": header,
        "ciphertext": cipherText,
    }

    jsonDict = dict()

    for name in msg:
        value = b64encode(msg[name]).decode('utf-8')
        print(f"{name:<15}: {value}")
        jsonDict[name] = value

    result = json.dumps(jsonDict)

    f = open('data/data.json', 'wb')
    f.write(result.encode('utf-8'))



