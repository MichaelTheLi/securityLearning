# Just play around with double ratchet algorythm

Note: all of this done only in learning purposes

## Tasks

1. Double-Ratchet encrypt-decrypt

    https://signal.org/docs/specifications/doubleratchet/
    
    https://github.com/Syndace/python-doubleratchet

2. Extended Triple-Diffie-Hellman exchange

    https://lianglouise.github.io/post/some_practice_on_implementing_signal_protocol_with_python_1/

## Result

Start with `start.py`, enter you `name`, works like login

Both users should be initialized for conversation to happen.

Messages received after sending message or on empty enter

## Conclusions

### Initial shared_secret
`shared_secret` should be established beforehand somehow.
1. In the first version x448 exchange from public_key used, not really secure way - anyone can give their public key instead of
2. Extended Triple Diffie-Hellman algorithm. To be fair - I don't see how its more "authenticated" - still no way to confirm key (pre-key bundle) is actually belongs to someone.
   
   As I see it - it more than a complicated public-key only if private keys are checked against some source of trust
3. Offline 
   
### Main mechanisms
   1. Establish `shared_secret` with your peer
   2. Initialize Double Ratchet.
      1. `shared_secret` is key used to derive `root_chain` key
      2. Initial `dh_pub` from initializing party used in DH ratchet
   3. Using Double Ratchet
      1. DH ratchet. Each party has `dh_priv` and `dh_pub`.
         1. Sender
            1. `dh_out` calculated by combining `receiver_dh_pub`and `own_dh_priv`
            2. `dh_out` used to initialize `root_chain` => `sending` chain
            3. Sender's `dh_pub` is sent alongside with the message
         2. Receiver
            1. Calculates same `dh_out` using `sender_dh_pub` from the message and `own_dh_priv`. This is used to initialized KDF chains and decrypt the message
            2. Generates new dh_pair. New received is sender, start from the top
      2. Root chain derived from `dh_out` and `shared_secret`
      3. Sending/Receiving chain derived from root_chain, https://signal.org/docs/specifications/doubleratchet/Set2_2.png
         
#### Notes

1. Sending/Receiving chains only grows if one party sends messages without receiving new for some time. If both party sends messages only after each other - chains are not growing


## Questions

1. ~~What are best practices for `shared_secret` sharing.~~ X3DH is used by signal. Not sure if there is anything more robust/widespread
2. What is `application_data`? Is it used for authentication, looks like it's also should be shared beforehand
3. What is the purpose of initial message and how to select it correctly?

## Next

1. TBD