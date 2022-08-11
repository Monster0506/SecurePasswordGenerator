from pwdGen import Password
from encrypt import AESCipher


class SecurePasword:
    def __init__(self, username, length=32, seed=None, master="key"):
        self._password_object = Password(length=length, seed=seed, username=username)
        self.cipher = AESCipher(master=master, salt=username)
        self.hash = self.cipher.encrypt(self._password_object.value)

    def decrypt(self):
        return self.cipher.decrypt(self.hash)

    def __str__(self):
        return str(self.hash)


if __name__ == "__main__":
    pwd = SecurePasword()
    print(pwd)
    print(pwd.decrypt())
