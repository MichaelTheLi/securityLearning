# Hashing strength

Note: all of this done only in learning purposes

## Tasks

1. Generate hashes with available algo
2. Try an "educated guess" brute-force, knowing algorithm and message length

## Result

For the "test" message all algos breaks in about 1 second

## Conclusion

1. Every algorithm broken in less than 1 second, there is no difference in breaking speed except the algorithm speed itself - only alphabet size and message length matters.
   1. Known algorithm significantly lowers problem-space 
   2. Known length significantly lowers problem-space
2. Short passwords are easily broken if no key-lengthening or salting applied 
3. Larger hash length doesn't provide more security against bruteforce, see https://stackoverflow.com/a/817121, https://stackoverflow.com/a/801116 and  https://security.stackexchange.com/questions/157520/which-hash-length-is-more-secure
4. Bruteforce attack != Preimage attack https://stackoverflow.com/questions/2772014/is-sha-1-secure-for-password-storage
5. Better algorithms trying to protect against collision attacks, but not helping with bruteforce of dictionary attacks - kinda modern and safe SHA-512 non-salted password hash can be broken easily if the password is "test". However, if hash is MD5 - one can find collision very quickly.   

## Next

1. https://en.wikipedia.org/wiki/PBKDF2
2. Salts