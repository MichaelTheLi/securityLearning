from base64 import b64encode

from learn.learnAsymmetric.rsa import encrypt
from learn.learnAsymmetric.users import getUser, getPublicUser, prepareUsers

if __name__ == '__main__':
    prepareUsers()
    data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam imperdiet tincidunt eros ut congue."

    print(f"Data in base64: {b64encode(data).decode('utf-8')}")
    print()

    sendingUser = getUser('user1', 'user1_passphrase')
    receivingUser = getPublicUser('user2')
    message = encrypt(data, receivingUser)
    print(message)
    message.save('user2')

    print("Sent to user2")



