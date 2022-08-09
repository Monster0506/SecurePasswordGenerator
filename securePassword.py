from pwdGen import Password
from encrypt import AESCipher


class SecurePasword:
    def __init__(self, size=32, seed=None, master="key"):
        self._password_object = Password(size, seed)
        self.cipher = AESCipher(master)
        self.password = self.cipher.encrypt(self._password_object.value)

    def decrypt(self):
        return self.cipher.decrypt(self.password)

    def __str__(self):
        return str(self.password)

    def __repr__(self):
        return self.password
