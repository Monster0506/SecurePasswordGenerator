""" Encrypt a plaintext, and decrypt it """
from base64 import b64decode, b64encode
from hashlib import sha256

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2


class Cipher(object):
    """A securely encrypted AES cipher.

    PLEASE USE THE API INSTEAD OF THIS CLASS
    Args:
        master: The master key to use for encryption
        salt: The salt to use for encryption
        secondary: Secondary keys for additional encryption
        public: public signing key for verifying the encryption

    Implements:
        encrypt: Encrypt a value with the master key, secondary keys, and salt
        decrypt: Decrypt a value
        _pad: Pad a string to 16 bytes
        _unpad: Unpad a string to 16 bytes
        verify_fingerprint: Verify the fingerprint of the encryption is the same as the one provided.
    """

    def __init__(self, master, salt, secondary, public="anonymous"):
        secondaries = "".join(
            sha256(str(key).encode()).hexdigest() for key in secondary
        )

        secondaries = sha256(secondaries.encode()).hexdigest().encode()
        salt = str(salt).encode()
        master_key = PBKDF2(master, str(salt).encode(), 32)
        salt_value = PBKDF2(str(salt).encode(), master_key, 32)
        self.block_size = AES.block_size
        kdf = PBKDF2(
            str(sha256(master_key + secondaries).hexdigest()), salt_value, 32, 1000
        )

        # create a fingerprint phrase for verifying the encryption
        self.public = str(sha256(public.encode()).hexdigest())
        fingerprint = (
            str(
                sha256(
                    str(sha256(salt_value + master_key + secondaries).hexdigest()).encode()
                ).hexdigest()
            )
            + self.public
        )
        self.fingerprint = fingerprint

        self.key = kdf[:32]

    def encrypt(self, raw) -> bytes:
        """Encrypt a value with the master key, secondary keys, and salt

        Args:
            raw (any [plaintext]): The value to encrypt

        Returns:
            bytes: The encrypted value
        """
        raw = self._pad(raw)
        init_vector = Random.new().read(AES.block_size)
        cypher = AES.new(self.key, AES.MODE_GCM, init_vector)
        return b64encode(init_vector + cypher.encrypt(raw.encode()))

    def decrypt(self, enc) -> str:
        """Decrypt a value with the master key, secondary keys, and salt

        Args:
            enc (binary str): The value to decrypt

        Returns:
            str: the decrypted value
        """
        enc = b64decode(enc)
        init_vector = enc[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, init_vector)
        return self._unpad(cipher.decrypt(enc[self.block_size :])).decode()

    def _pad(self, string: str) -> str:
        """Pad a string to 16 bytes

        Args:
            string (str): string to be padded

        Returns:
            str: the padded string
        """
        return string + (self.block_size - len(string) % self.block_size) * chr(
            self.block_size - len(string) % self.block_size
        )

    @staticmethod
    def _unpad(string):
        """Unpad a string from 16 bytes

        Args:
            string (str): string to be unpadded

        Returns:
            str: unpadded string
        """
        return string[
            : -ord(string[len(string) - 1 :])
        ]  # sourcery skip: simplify-negative-index

    def verify_fingerprint(self, fingerprint: str) -> bool:
        """Determine if the ciphers' are the same.

        Args:
            fingerprint (str): the fingerprint of the other cipher

        Returns:
            bool: True if the fingerprints are the same, False otherwise
        """
        return self.fingerprint == fingerprint
