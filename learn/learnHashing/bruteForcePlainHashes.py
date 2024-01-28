import hashlib
import itertools
import string
from time import perf_counter_ns

from learn.learnHashing import hashing

if __name__ == '__main__':
    hashing.outputDifferentHashes("test")
    hashes = hashing.getDifferentHashes("test")

    alphabet = string.ascii_lowercase
    print('Alphabet used: ', alphabet)

    for hashObj in hashes:
        print(f"Trying to break {hashObj.algo}:{hashObj.digest}")
        start = perf_counter_ns()
        hashing.bruteForceHash(hashObj, alphabet)
        end = perf_counter_ns()
        timeElapsed = (end - start) / 1000 / 1000
        print(f"Fixed-width {hashObj.algo} broken in {timeElapsed:<5.2f}ms")

