""" Encrypt a plaintext, and decrypt it """
from base64 import b64encode, b64decode
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random


class AESCipher(object):
<<<<<<< HEAD
    def __init__(self, master, salt=b"insecure salt", secondary=""):
        # TODO: maybe make secondary be a list of secondary keys?
        print("TODO: make secondary be a list of secondary keys?")
        salt = str(salt).encode()
        master_key = PBKDF2(master, str(salt).encode(), 32)
        salt_value = PBKDF2(str(salt).encode(), master_key, 32)
=======

    def __init__(self, master: str = "key", salt: str = "salt"):
        master_key = PBKDF2(master, salt.encode(), 32)
        salt_value = PBKDF2(salt, master_key, 32)
>>>>>>> 157203cdbd4b1e0ff0a91c766f9eeb8fd0230da9
        self.block_size = AES.block_size
        kdf = PBKDF2(
            str(sha256(master_key + str(secondary).encode()).hexdigest()),
            salt_value,
            32,
            1000,
        )
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
        init_vector = enc[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, init_vector)
<<<<<<< HEAD
        return self._unpad(cipher.decrypt(enc[self.block_size :])).decode()
=======
        return self._unpad(cipher.decrypt(
            enc[self.block_size:])).decode("utf-8")
>>>>>>> 157203cdbd4b1e0ff0a91c766f9eeb8fd0230da9

    def _pad(self, string: str):
        "Pad a string to 16 bytes"
        return string + (self.block_size - len(string) %
                         self.block_size) * chr(self.block_size -
                                                len(string) % self.block_size)

    @staticmethod
    def _unpad(string):
        """Unpad a string from 16 bytes"""
        unpadded = string[:-ord(string[len(string) - 1:])]
        return unpadded
