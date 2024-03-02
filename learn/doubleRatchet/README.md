# Just play around with double ratchet algorythm

Note: all of this done only in learning purposes

## Tasks

1. Double-Ratchet encrypt-decrypt

https://signal.org/docs/specifications/doubleratchet/

https://github.com/Syndace/python-doubleratchet



## Result

Start with `start.py`, enter you `name`, works like login

Both users should be initialized for conversation to happen.

Messages received after sending message or on empty enter

## Conclusions

1. `shared_secret` should be established beforehand somehow.
    In this example exchange from public_key used, not sure if it's correct
2. Main mechanisms:
   1. Obtain `shared_secret` with your peer
   2. ?
3. 

## Questions

1. What are best practices for `shared_secret` sharing. Diffie-Hellman?
2. What is `application_data`? Is it used for authentication, looks like it's also should be shared beforehand
3. What is the purpose of initial message and how to select it correctly?

## Next

1. TBD