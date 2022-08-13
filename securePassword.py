from encrypt import AESCipher
from pwdgen import Password


class SecurePasword:

    def __init__(
        self,
        username: str,
        website: str,
        private_key,
        length: int = 32,
        master: str = "key",
    ):
        self._password_object = Password(username=username,
                                         length=length,
                                         website=website,
                                         private_key=private_key)
        self.cipher = AESCipher(master=master, salt=username)
        self.hash = self.cipher.encrypt(self._password_object.value)
        self.username = username
        self.website = website
        self.length = length
        self.master = master
        self.seed = private_key

    def decrypt(self) -> str:
        """Decrypt the password"""
        return self.cipher.decrypt(self.hash)

    def __str__(self) -> str:
        return str(self.hash)

    def __len__(self) -> int:
        return len(self.hash)
