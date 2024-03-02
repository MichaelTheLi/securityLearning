# Just play around with asymmetric encryption

Note: all of this done only in learning purposes

## Tasks

1. Asymmetric encrypt-decrypt
   1. RSA

https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa
https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html

## Result

Run [encrypt.py](encrypt.py) then [decrypt.py](decrypt.py)

Files in folders of `data` used to emulate different users

### Cases

#### Simple encrypt

1. `encrypt.py`
   1. Message is encrypted with `user2` publicKey 
2. `descrypt.py`
   1. Message is decrypted with `user2` privateKey

#### Signed encrypt

1. `encryptSigned.py`
   1. Message is encrypted with `user2` publicKey
   2. Message is signed with `user1` (sender) privateKey
2. `descryptSigned.py`
   1. Message is decrypted with `user2` privateKey
   2. Signature is checked with `user1` (sender) publicKey
3. `hijackAttemptEncryptSigned.py`
   1. Message is encrypted with `user2` publicKey
   2. Message is signed with `badPerson` privateKey
   3. `descryptSigned` won't trust this message

## Conclusions

1. Authentication is a separate concert from publicKey cryptography. Only generating part and private-key owner can know what is inside the message. But message itself is not guaranty what receiver got the message from someone he expected, Anyone can encrypt data with publicKey.
   
   Sender, Bob, can sign a message with their private key, and Alice can check if it's really sent by Bob by checking signature againts Bob's publicKey. publicKey identity is a different story. Chain of trust, is it you?  
2. ?

## Questions

1. What to sign? Encrypted? Raw? Session-Key? All message?

## Next

1. Try EllipticCurve?