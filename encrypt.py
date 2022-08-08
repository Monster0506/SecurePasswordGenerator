from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random

from base64 import b64encode, b64decode





class AESCipher(object):
    def __init__(self, key="key"):
        self.bs = AES.block_size
        kdf = PBKDF2(key.encode(), bin(63557).encode(), 64, 1000)
        self.key = kdf[:32]

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cypher = AES.new(self.key, AES.MODE_GCM, iv)
        return b64encode(iv + cypher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[: AES.block_size]
        cypher = AES.new(self.key, AES.MODE_GCM, iv)
        return self._unpad(cypher.decrypt(enc[AES.block_size :])).decode("utf-8")

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        unpadded = s[:-ord(s[len(s) - 1:])]
        return unpadded
    
    
if __name__ == "__main__":
    cipher = AESCipher("key")
    encrypted = cipher.encrypt("Hello World")
    print("Encrypted:", encrypted)
    decrypted = cipher.decrypt(encrypted)
    print("Decrypted:", decrypted)
