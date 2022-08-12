from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random

from base64 import b64encode, b64decode


class AESCipher(object):
    def __init__(self, master: str = "key", salt: str = "salt"):
        master = PBKDF2(master, salt.encode(), 32)
        salt = PBKDF2(salt, master, 32)
        self.bs = AES.block_size
        kdf = PBKDF2(master, salt, 32, 1000)
        self.key = kdf[:32]

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cypher = AES.new(self.key, AES.MODE_GCM, iv)
        return b64encode(iv + cypher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[: self.bs]
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        return self._unpad(cipher.decrypt(enc[self.bs :])).decode("utf-8")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        unpadded = s[: -ord(s[len(s) - 1 :])]
        return unpadded

    def __str__(self) -> str:
        return str(self.password)

    def __repr__(self) -> str:
        return self.password
