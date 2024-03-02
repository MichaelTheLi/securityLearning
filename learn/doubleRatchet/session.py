import base64
import json
import os
import pickle
from collections import defaultdict
from pathlib import Path
from typing import List, Optional, Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from doubleratchet import EncryptedMessage, DuplicateMessageException

from learn.doubleRatchet.dr import DoubleRatchet, dr_configuration
from learn.doubleRatchet.user import User, PublicUser

class SessionMessages:
    def __init__(self):
        self.messages: Dict[str, List[EncryptedMessage]] = defaultdict(list)
        self.initializeMessage: Optional[EncryptedMessage] = None


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

        conversationPointed = self.user.name + '_dr_for_' + self.other.name
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
        print(f"{bcolors.WARNING}{header}: {msg}{bcolors.ENDC}")

    def dumpData(self):
        with open(self.storagePath, "wb") as deferred_bin:
            pickle.dump(self.messages, deferred_bin)

        with open(self.dr_path, "w", encoding="utf-8") as dr_json:
            json.dump(self.dr.json, dr_json)

    async def initializeIfNeeded(self):
        conversation = self.user.name + '_dr_for_' + self.other.name
        path = Path("private_storage/" + conversation + ".json")

        if not os.path.exists(self.storagePath):
            message = await self.firstInitialize()
            if message:
                self.messages.initializeMessage = message
        else:
            with open(self.storagePath, "rb") as deferred_bin:
                self.messages = pickle.load(deferred_bin)

            if self.messages.initializeMessage:
                res = await self.secondaryInitializeWith(self.messages.initializeMessage)

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
            key = X448PrivateKey.from_private_bytes(self.user.privateKey)
            shared_secret = key.exchange(X448PublicKey.from_public_bytes(self.other.publicKey))

            self.dr, initial_message_encrypted = await DoubleRatchet.encrypt_initial_message(
                shared_secret=shared_secret[:32],
                recipient_ratchet_pub=self.other.publicKey,
                message=self.ad.encode('utf-8'),
                associated_data=self.ad.encode('utf-8'),
                **dr_configuration
            )

            return initial_message_encrypted

    async def secondaryInitializeWith(self, initial_message: EncryptedMessage) -> bool:
        conversation = self.user.name + '_dr_for_' + self.other.name
        if self.dr_path.exists():
            with open(self.dr_path, "r", encoding="utf-8") as dr_json:
                self.dr = DoubleRatchet.from_json(json.load(dr_json), **dr_configuration)
            return True
        else:
            key = X448PrivateKey.from_private_bytes(self.user.privateKey)
            shared_secret = key.exchange(X448PublicKey.from_public_bytes(self.other.publicKey))

            self.dr, initial_message_decrypted = await DoubleRatchet.decrypt_initial_message(
                shared_secret=shared_secret[:32],
                own_ratchet_priv=self.user.privateKey,
                message=initial_message,
                associated_data=self.ad.encode('utf-8'),
                **dr_configuration
            )

            return initial_message_decrypted == self.ad.encode('utf-8')
