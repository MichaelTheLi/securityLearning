import hashlib
import itertools


class HashTest:
    def __init__(self, msg: str, digest: str, algo: str):
        self.digest = digest
        self.algo = algo
        self.msg = msg


def outputDifferentHashes(message: str):
    hashes = getDifferentHashes(message)
    for hash in hashes:
        print(f"{hash.algo:>15}: {hash.digest}")


def getDifferentHashes(message: str):
    r = []
    for algo in hashlib.algorithms_available:
        hashRes = hashlib.new(algo, message.encode('utf-8'))
        if hashRes.name.startswith('shake'):
            digest = hashRes.hexdigest(64)
        else:
            digest = hashRes.hexdigest()
        r.append(HashTest(message, digest, algo))
    return r


def bruteForceHash(hashObj: HashTest, alphabet: str):
    for permute in itertools.product(alphabet, repeat=len(hashObj.msg)):
        candidate = "".join(permute)
        candidateHash = hashlib.new(hashObj.algo, candidate.encode('utf-8'))

        if candidateHash.name.startswith('shake'):
            candidateHashDigest = candidateHash.hexdigest(len(hashObj.digest))
        else:
            candidateHashDigest = candidateHash.hexdigest()

        if candidateHashDigest == hashObj.digest:
            return candidate
