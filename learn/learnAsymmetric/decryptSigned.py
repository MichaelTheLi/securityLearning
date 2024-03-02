from learn.learnAsymmetric.rsa_signed import decryptSigned, RSASignedMessage
from learn.learnAsymmetric.users import getUser, getPublicUser, prepareUsers

if __name__ == '__main__':
    prepareUsers()
    receivingUser = getUser('user2', 'user2_passphrase')
    sendingUser = getPublicUser('user1')

    msg = RSASignedMessage.fromFile('data/user2/incoming_message.json')
    data = decryptSigned(msg, sendingUser, receivingUser)

    print(f"Decrypted: {data.decode('utf-8')}")




