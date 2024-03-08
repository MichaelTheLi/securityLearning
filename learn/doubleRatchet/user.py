import base64
import json
import os
import random
from pathlib import Path
from typing import List

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey


class PreKeyBundle:
    def __init__(self,
                 ik_pub: bytes,
                 spk_pub: bytes,
                 spk_sig: bytes,
                 opk_pub: bytes,
                 opk_pub_idx: int,
                 ephemeral_pub: bytes,
                 ):
        self.ik_pub = ik_pub
        self.spk_pub = spk_pub
        self.spk_sig = spk_sig
        self.opk_pub = opk_pub
        self.opk_pub_idx = opk_pub_idx
        self.ephemeral_pub = ephemeral_pub

    def toJson(self, path: Path):
        with open(path, "w", encoding="utf-8") as jsonFile:
            data = {
                'ik_pub': base64.b64encode(self.ik_pub).decode('utf-8'),
                'spk_pub': base64.b64encode(self.spk_pub).decode('utf-8'),
                'spk_sig': base64.b64encode(self.spk_sig).decode('utf-8'),
                'opk_pub': base64.b64encode(self.opk_pub).decode('utf-8'),
                'opk_pub_idx': self.opk_pub_idx,
                'ephemeral_pub': base64.b64encode(self.ephemeral_pub).decode('utf-8'),
            }
            json.dump(data, jsonFile)

    @staticmethod
    def fromJson(path: Path):
        if path.exists():
            with open(path, "r", encoding="utf-8") as jsonFile:
                json_parsed = json.load(jsonFile)
                return PreKeyBundle(
                    base64.b64decode(json_parsed['ik_pub']),
                    base64.b64decode(json_parsed['spk_pub']),
                    base64.b64decode(json_parsed['spk_sig']),
                    base64.b64decode(json_parsed['opk_pub']),
                    json_parsed['opk_pub_idx'],
                    base64.b64decode(json_parsed['ephemeral_pub']),
                )


class PrivateKeysBundle:
    def __init__(self,
                 ik: bytes,
                 spk: bytes,
                 opks: List[bytes],
                 ephemeral: bytes,
                 ):
        self.ik = ik
        self.spk = spk
        self.opks = opks
        self.ephemeral = ephemeral

    def toJson(self, path: Path):
        with open(path, "w", encoding="utf-8") as jsonFile:
            data = {
                'ik': base64.b64encode(self.ik).decode('utf-8'),
                'spk': base64.b64encode(self.spk).decode('utf-8'),
                'opks': list(map(lambda x: base64.b64encode(x).decode('utf-8'), self.opks)),
                'ephemeral': base64.b64encode(self.ephemeral).decode('utf-8'),
            }
            json.dump(data, jsonFile)

    @staticmethod
    def fromJson(path: Path):
        if path.exists():
            with open(path, "r", encoding="utf-8") as jsonFile:
                json_parsed = json.load(jsonFile)
                return PrivateKeysBundle(
                    base64.b64decode(json_parsed['ik']),
                    base64.b64decode(json_parsed['spk']),
                    list(map(base64.b64decode, json_parsed['opks'])),
                    base64.b64decode(json_parsed['ephemeral']),
                )

    @staticmethod
    def create(name: str):
        storagePath = PrivateKeysBundle.initializeStorage(name)
        path = Path(str(storagePath) + '/privateBundle.json')
        if path.exists():
            return PrivateKeysBundle.fromJson(path)
        else:
            ik = X448PrivateKey.generate()
            spk = X448PrivateKey.generate()
            ephemeral = X448PrivateKey.generate()
            opks = []
            for i in range(10):
                opk = X448PrivateKey.generate()
                opks.append(opk.private_bytes_raw())
            r = PrivateKeysBundle(
                ik.private_bytes_raw(),
                spk.private_bytes_raw(),
                opks,
                ephemeral.private_bytes_raw()
            )
            r.toJson(path)
            return r

    def getPreKeyBundle(self) -> PreKeyBundle:
        ik_pub = X448PrivateKey.from_private_bytes(self.ik).public_key()
        spk_pub = X448PrivateKey.from_private_bytes(self.spk).public_key()

        # signerKey = Ed448PrivateKey.from_private_bytes(self.ik) # TODO Convert X448 to Ed448?
        # spk_sig = signerKey.sign(spk_pub.public_bytes_raw())
        spk_sig = b'none'

        rnd = random.Random()
        selectedOpkIdx = rnd.randint(0, len(self.opks) - 1)
        selectedOpk = self.opks[selectedOpkIdx]
        opk_pub = X448PrivateKey.from_private_bytes(selectedOpk).public_key()

        ephemeral_pub = X448PrivateKey.from_private_bytes(self.ephemeral).public_key()

        return PreKeyBundle(
            ik_pub.public_bytes_raw(),
            spk_pub.public_bytes_raw(),
            spk_sig,
            opk_pub.public_bytes_raw(),
            selectedOpkIdx,
            ephemeral_pub.public_bytes_raw(),
        )

    @staticmethod
    def initializeStorage(name: str) -> Path:
        privatePath = Path("private_storage/" + name)
        storagePath = Path("storage")

        if not privatePath.exists():
            os.makedirs(privatePath)

        if not storagePath.exists():
            os.makedirs(storagePath)

        return privatePath


class PublicUser:
    def __init__(self, name: str, preKeyBundle: PreKeyBundle):
        self.name = name
        self.preKeyBundle = preKeyBundle

    @staticmethod
    def findRegistered(name):
        path = Path("storage/" + name + '_pre_bundle.json')

        if path.exists():
            return PublicUser(name, PreKeyBundle.fromJson(path))
        else:
            raise Exception('User ' + name + ' not found')


class User:
    def __init__(self, name: str, privateKeysBundle: PrivateKeysBundle):
        self.name = name
        self.privateKeysBundle = privateKeysBundle

    @staticmethod
    def create(name: str):
        privateKeysBundle = PrivateKeysBundle.create(name)

        return User(
            name,
            privateKeysBundle
        )

    def register(self):
        path = Path("storage/" + self.name + '_pre_bundle.json')
        preKeyBundle = self.privateKeysBundle.getPreKeyBundle()
        preKeyBundle.toJson(path)
