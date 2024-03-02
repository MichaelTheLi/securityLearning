from learn.learnAsymmetric.rsa import decrypt, RSAMessage
from learn.learnAsymmetric.users import getUser, getPublicUser, prepareUsers

if __name__ == '__main__':
    prepareUsers()
    receivingUser = getUser('user2', 'user2_passphrase')
    sendingUser = getPublicUser('user1')

    msg = RSAMessage.fromFile('data/user2/incoming_message.json')
    data = decrypt(msg, receivingUser)

    print(f"Decrypted: {data.decode('utf-8')}")




