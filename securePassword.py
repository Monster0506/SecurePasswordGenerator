from encrypt import AESCipher
from pwdgen import Password


class SecurePasword:
    def __init__(
        self,
        seed,
        master,
        username: str,
        website: str,
<<<<<<< HEAD
=======
        seed,
        gen_code=None,
>>>>>>> 157203cdbd4b1e0ff0a91c766f9eeb8fd0230da9
        length: int = 32,
        secondary=None,
        salt=b"insecure salt",
    ):
<<<<<<< HEAD

        self._password_object = Password(
            username=username, length=length, website=website, seed=seed
        )
        self.cipher = AESCipher(master=master, salt=salt, secondary=secondary)
=======
        self._password_object = Password(username=username,
                                         gen_code=gen_code,
                                         length=length,
                                         website=website,
                                         seed=seed)
        self.cipher = AESCipher(master=master, salt=username)
>>>>>>> 157203cdbd4b1e0ff0a91c766f9eeb8fd0230da9
        self.hash = self.cipher.encrypt(self._password_object.value)

    def decrypt(self) -> str:
        """Decrypt the password"""
        return self.cipher.decrypt(self.hash)

    def __str__(self) -> str:
        return str(self.hash)

    def __len__(self) -> int:
        return len(self.hash)
