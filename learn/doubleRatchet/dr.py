from typing import Any, Dict

from doubleratchet import DoubleRatchet as DR, Header
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs
)


class DoubleRatchet(DR):
    """
    An example of a Double Ratchet implementation used in the chat.
    """

    @staticmethod
    def _build_associated_data(associated_data: bytes, header: Header) -> bytes:
        return (
            associated_data
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


class DiffieHellmanRatchet(dhr448.DiffieHellmanRatchet):
    """
    Use the recommended X448-based Diffie-Hellman ratchet implementation in this example.
    """


class AEAD(aead_aes_hmac.AEAD):
    """
    Use the recommended AES/HMAC-based AEAD implementation in this example, with SHA-512 and a fitting info
    string.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat AEAD".encode("ASCII")


class RootChainKDF(kdf_hkdf.KDF):
    """
    Use the recommended HKDF-based KDF implementation for the root chain in this example, with SHA-512 and a
    fitting info string.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return "Double Ratchet Chat Root Chain KDF".encode("ASCII")


class MessageChainKDF(kdf_separate_hmacs.KDF):
    """
    Use the recommended separate HMAC-based KDF implementation for the message chain in this example, with
    truncated SHA-512.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256


# Configuration of the DoubleRatchet class, which has to be passed to each constructing method
# (encrypt_initial_message, decrypt_initial_message, deserialize).
dr_configuration: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": DiffieHellmanRatchet,
    "root_chain_kdf": RootChainKDF,
    "message_chain_kdf": MessageChainKDF,
    "message_chain_constant": b"\x01\x02",
    "dos_protection_threshold": 100,
    "max_num_skipped_message_keys": 1000,
    "aead": AEAD
}

