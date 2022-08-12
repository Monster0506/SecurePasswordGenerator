from pwdGen import Password
from encrypt import AESCipher


class SecurePasword:
    def __init__(
        self,
        username: str,
        website: str,
        length: int = 32,
        seed=None,
        master: str = "key",
    ):
        self._password_object = Password(
            username=username, length=length, website=website, seed=seed
        )
        self.cipher = AESCipher(master=master, salt=username)
        self.hash = self.cipher.encrypt(self._password_object.value)

    def decrypt(self) -> str:
        return self.cipher.decrypt(self.hash)

    def __str__(self) -> str:
        return str(self.hash)

    def __len__(self) -> int:
        return len(self.hash)
    
