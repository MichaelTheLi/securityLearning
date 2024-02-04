# Just play around with encryption

Note: all of this done only in learning purposes

## Tasks

1. AES encrypt-decrypt

https://pycryptodome.readthedocs.io/en/latest/src/examples.html

## Result

Run [encrypt.py](encrypt.py) then [decrypt.py](decrypt.py)

Files in `data` used to emulate different users

## Conclusions

1. Not only cipherText is transmitted
   1. `tag` - [MAC(Message Authentication Code)](https://en.wikipedia.org/wiki/Message_authentication_code):
      
      With encryption alone, the receiver is not able to detect if the ciphertext (i.e., the encrypted data) was modified while in transit. 
      Modern usage encourages message authentication, as described [here](https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#)
   2. `nonce` - [single-use number](https://en.wikipedia.org/wiki/Cryptographic_nonce) used as Initialization Vector
   
      Fun fact: turns out to be a [linguistic term](https://en.wikipedia.org/wiki/Nonce_word)  
      > Randomization is crucial for some encryption schemes to achieve semantic security, a property whereby repeated usage of the scheme under the same key does not allow an attacker to infer relationships between (potentially similar) segments of the encrypted message. For block ciphers, the use of an IV is described by the modes of operation.

      > The key, which is given as one input to the cipher, defines the mapping between plaintext and ciphertext. If data of arbitrary length is to be encrypted, a simple strategy is to split the data into blocks each matching the cipher's block size, and encrypt each block separately using the same key. This method is not secure as equal plaintext blocks get transformed into equal ciphertexts, and a third party observing the encrypted data may easily determine its content even when not knowing the encryption key.
2. Some public data can be transmitted with the data in plain text, but covered by MAC authentication.
3. Cipher text is short if encoded data is short

## Next

1. Public-Key crypt
2. Padding?