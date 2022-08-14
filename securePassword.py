from encrypt import AESCipher
from pwdgen import Password


class SecurePasword:

    def __init__(
        self,
        username: str,
        website: str,
        seed,
        gen_code=None,
        length: int = 32,
        master: str = "key",
    ):
        self._password_object = Password(username=username,
                                         gen_code=gen_code,
                                         length=length,
                                         website=website,
                                         seed=seed)
        self.cipher = AESCipher(master=master, salt=username)
        self.hash = self.cipher.encrypt(self._password_object.value)
        self.username = username
        self.website = website
        self.length = length
        self.master = master
        self.seed = seed

    def decrypt(self) -> str:
        """Decrypt the password"""
        return self.cipher.decrypt(self.hash)

    def __str__(self) -> str:
        return str(self.hash)

    def __len__(self) -> int:
        return len(self.hash)
