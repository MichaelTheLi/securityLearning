import base64
import json
import os
import pickle
from collections import defaultdict
from pathlib import Path
from typing import List, Optional, Dict, Tuple

from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from doubleratchet import EncryptedMessage, DuplicateMessageException

from learn.doubleRatchet.colors import Colors
from learn.doubleRatchet.dr import DoubleRatchet, dr_configuration
from learn.doubleRatchet.user import User, PublicUser


class SessionMessages:
    def __init__(self):
        self.messages: Dict[str, List[EncryptedMessage]] = defaultdict(list)
        self.initializeMessage: Optional[EncryptedMessage] = None
        self.preBundleUsed: Optional[int] = None


class Session:
    def __init__(self, user: User, other: PublicUser):
        self.user = user
        self.other = other
        self.messages: Optional[SessionMessages] = None

        self.conversation = '_'.join(sorted([self.user.name, self.other.name]))
        self.ad = self.conversation
        self.storagePath = os.path.join('storage', self.conversation + ".pickle")

        try:
            with open(self.storagePath, "rb") as deferred_bin:
                self.messages = pickle.load(deferred_bin)
        except:
            self.messages = SessionMessages()

        conversationPointed = self.user.name + '/dr_for_' + self.other.name
        self.dr_path = Path("private_storage/" + conversationPointed + ".json")

    async def sendMessage(self, message: str):
        await self.initializeIfNeeded()

        message_encrypted = await self.dr.encrypt_message(message.encode("UTF-8"), self.ad.encode('utf-8'))
        self.messages.messages[self.other.name].append(message_encrypted)

        self.dumpData()

    async def readMessages(self) -> List[Tuple[str, List[Tuple[str, str]]]]:
        await self.initializeIfNeeded()

        messages: List[Tuple[str, List[Tuple[str, str]]]] = []
        for message in self.messages.messages[self.user.name]:
            try:
                message_decrypted = await self.dr.decrypt_message(message, self.ad.encode('utf-8'))
                item = (
                    message_decrypted.decode('UTF-8'),
                    self.debugData(message)
                )
                messages.append(item)
            except DuplicateMessageException:
                print("duplicate_message", message)
        self.messages.messages[self.user.name] = []

        self.dumpData()

        return messages

    @staticmethod
    def debugData(message: EncryptedMessage) -> List[Tuple[str, str]]:
        return [
            ('Header_pub', base64.b64encode(message.header.ratchet_pub).decode('utf-8')),
            ('Sending chain', str(message.header.sending_chain_length)),
            ('Previous sending chain', str(message.header.previous_sending_chain_length)),
            ('Previous sending chain', str(message.header.previous_sending_chain_length)),
            ('Message', base64.b64encode(message.ciphertext).decode('utf-8'))
        ]

    @staticmethod
    def printDebugLine(header: str, msg: str):
        print(f"{Colors.WARNING}{header}: {msg}{Colors.ENDC}")

    def dumpData(self):
        with open(self.storagePath, "wb") as deferred_bin:
            pickle.dump(self.messages, deferred_bin)

        with open(self.dr_path, "w", encoding="utf-8") as dr_json:
            json.dump(self.dr.json, dr_json)

    async def initializeIfNeeded(self):
        conversation = self.user.name + '/dr_for_' + self.other.name
        path = Path("private_storage/" + conversation + ".json")

        if not os.path.exists(self.storagePath):
            message = await self.firstInitialize()
            if message:
                self.messages.initializeMessage = message
                self.messages.preBundleUsed = self.other.preKeyBundle.opk_pub_idx
        else:
            with open(self.storagePath, "rb") as deferred_bin:
                self.messages = pickle.load(deferred_bin)

            if self.messages.initializeMessage:
                res = await self.secondaryInitializeWith(self.messages.initializeMessage, self.messages.preBundleUsed)

                if not res:
                    raise Exception('Initial message check failed')
            elif self.dr is None:
                with open(path, "r", encoding="utf-8") as dr_json:
                    self.dr = DoubleRatchet.from_json(json.load(dr_json), **dr_configuration)

    async def firstInitialize(self) -> Optional[EncryptedMessage]:
        if self.dr_path.exists():
            with open(self.dr_path, "r", encoding="utf-8") as dr_json:
                self.dr = DoubleRatchet.from_json(json.load(dr_json), **dr_configuration)
            return None
        else:
            shared_secret = self.calculateInitialX3dh()
            print('Secret: ', base64.b64encode(shared_secret).decode('utf-8'))
            self.dr, initial_message_encrypted = await DoubleRatchet.encrypt_initial_message(
                shared_secret=shared_secret,
                recipient_ratchet_pub=self.other.preKeyBundle.spk_pub,
                message=self.ad.encode('utf-8'),
                associated_data=self.ad.encode('utf-8'),
                **dr_configuration
            )

            return initial_message_encrypted

    async def secondaryInitializeWith(self, initial_message: EncryptedMessage, bundleUsed: int) -> bool:
        if self.dr_path.exists():
            with open(self.dr_path, "r", encoding="utf-8") as dr_json:
                self.dr = DoubleRatchet.from_json(json.load(dr_json), **dr_configuration)
            return True
        else:
            shared_secret = self.calculateSecondaryX3dh(bundleUsed)
            print('Secret: ', base64.b64encode(shared_secret).decode('utf-8'))

            self.dr, initial_message_decrypted = await DoubleRatchet.decrypt_initial_message(
                shared_secret=shared_secret,
                own_ratchet_priv=self.user.privateKeysBundle.spk,
                message=initial_message,
                associated_data=self.ad.encode('utf-8'),
                **dr_configuration
            )

            return initial_message_decrypted == self.ad.encode('utf-8')

    def calculateInitialX3dh(self) -> bytes:
        mine_ik = X448PrivateKey.from_private_bytes(self.user.privateKeysBundle.ik)
        other_spk = X448PublicKey.from_public_bytes(self.other.preKeyBundle.spk_pub)
        DH_1 = mine_ik.exchange(other_spk)

        mine_ek = X448PrivateKey.from_private_bytes(self.user.privateKeysBundle.ephemeral)

        other_ik = X448PublicKey.from_public_bytes(self.other.preKeyBundle.ik_pub)
        other_spk = X448PublicKey.from_public_bytes(self.other.preKeyBundle.spk_pub)
        other_opk = X448PublicKey.from_public_bytes(self.other.preKeyBundle.opk_pub)
        DH_2 = mine_ek.exchange(other_ik)
        DH_3 = mine_ek.exchange(other_spk)
        DH_4 = mine_ek.exchange(other_opk)


        print('mine_ek', base64.b64encode(mine_ek.public_key().public_bytes_raw()).decode('utf-8'))
        print('other_opk', base64.b64encode(other_opk.public_bytes_raw()).decode('utf-8'))

        # key = Ed448PublicKey.from_public_bytes(other_ik.public_bytes_raw() + b"=")
        # try:
        #     key.verify(self.other.preKeyBundle.spk_sig, other_spk.public_bytes_raw())
        # except ValueError:
        #     print('Unable to verify Signed Prekey')
        #     raise ValueError

        print('dh1', base64.b64encode(DH_1).decode('utf-8'))
        print('dh2', base64.b64encode(DH_2).decode('utf-8'))
        print('dh3', base64.b64encode(DH_3).decode('utf-8'))
        print('dh4', base64.b64encode(DH_4).decode('utf-8'))

        return HKDF(
            DH_1 + DH_2 + DH_3 + DH_4,
            key_len=32,
            salt=b"",
            hashmod=SHA512,
        )

    def calculateSecondaryX3dh(self, bundleUsed: int) -> bytes:
        mine_spk = X448PrivateKey.from_private_bytes(self.user.privateKeysBundle.spk)
        other_ik = X448PublicKey.from_public_bytes(self.other.preKeyBundle.ik_pub)
        DH_1 = mine_spk.exchange(other_ik)

        mine_ik = X448PrivateKey.from_private_bytes(self.user.privateKeysBundle.ik)
        mine_opk = X448PrivateKey.from_private_bytes(self.user.privateKeysBundle.opks[bundleUsed])

        other_ek = X448PublicKey.from_public_bytes(self.other.preKeyBundle.ephemeral_pub)
        DH_2 = mine_ik.exchange(other_ek)
        DH_3 = mine_spk.exchange(other_ek)
        DH_4 = mine_opk.exchange(other_ek)

        print('other_ek', base64.b64encode(self.other.preKeyBundle.ephemeral_pub).decode('utf-8'))
        print('mine_opk', base64.b64encode(mine_opk.public_key().public_bytes_raw()).decode('utf-8'))
        print('opk_idx', self.other.preKeyBundle.opk_pub_idx)

        for opk in self.user.privateKeysBundle.opks:
            print('mine_opk', base64.b64encode(X448PrivateKey.from_private_bytes(opk).public_key().public_bytes_raw()).decode('utf-8'))

        print('dh1', base64.b64encode(DH_1).decode('utf-8'))
        print('dh2', base64.b64encode(DH_2).decode('utf-8'))
        print('dh3', base64.b64encode(DH_3).decode('utf-8'))
        print('dh4', base64.b64encode(DH_4).decode('utf-8'))

        # other_spk = X448PublicKey.from_public_bytes(self.other.preKeyBundle.spk_pub)

        # key = Ed448PublicKey.from_public_bytes(other_ik.public_bytes_raw() + b"=")
        # try:
        #     key.verify(self.other.preKeyBundle.spk_sig, other_spk.public_bytes_raw())
        # except ValueError:
        #     print('Unable to verify Signed Prekey')
        #     raise ValueError

        return HKDF(
            DH_1 + DH_2 + DH_3 + DH_4,
            key_len=32,
            salt=b"",
            hashmod=SHA512,
        )
