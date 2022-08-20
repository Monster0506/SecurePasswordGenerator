""" Encrypt a plaintext, and decrypt it """
from base64 import b64encode, b64decode
from hashlib import sha256
from os import stat

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random


class AESCipher(object):
    def __init__(
        self, master, salt=b"insecure salt", secondary: list = "", public="public"
    ):
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
        fingerprint = sha256(kdf + str(public).encode()).hexdigest()
        self.fingerprint = fingerprint
        self.key = kdf[:32]

    def encrypt(self, raw):
        """Encrypt a raw plaintext"""
        raw = self._pad(raw)
        init_vector = Random.new().read(AES.block_size)
        cypher = AES.new(self.key, AES.MODE_GCM, init_vector)
        return b64encode(init_vector + cypher.encrypt(raw.encode()))

    def decrypt(self, enc):
        """Decrypt a encoding"""
        enc = b64decode(enc)
        init_vector = enc[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, init_vector)
        return self._unpad(cipher.decrypt(enc[self.block_size :])).decode()

    def _pad(self, string: str):
        "Pad a string to 16 bytes"
        return string + (self.block_size - len(string) % self.block_size) * chr(
            self.block_size - len(string) % self.block_size
        )

    @staticmethod
    def _unpad(string):
        """Unpad a string from 16 bytes"""
        return string[
            : -ord(string[len(string) - 1 :])
        ]  # sourcery skip: simplify-negative-index

    def verify_fingerprint(self, fingerprint):
        return self.fingerprint == fingerprint

    
