from encrypt import AESCipher
from pwdgen import Password


class SecurePasword:
    def __init__(
        self,
        seed,
        master,
        username: str,
        website: str,
        length: int = 32,
        secondary=None,
        salt=b"insecure salt",
    ):

        self._password_object = Password(
            username=username, length=length, website=website, seed=seed
        )
        self.cipher = AESCipher(master=master, salt=salt, secondary=secondary)
        self.hash = self.cipher.encrypt(self._password_object.value)

    def decrypt(self) -> str:
        """Decrypt the password"""
        return self.cipher.decrypt(self.hash)

    def __str__(self) -> str:
        return str(self.hash)

    def __len__(self) -> int:
        return len(self.hash)
