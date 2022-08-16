from encrypt import AESCipher
from pwdgen import Password


class _Dummy(object):
    def __init__(self, password):
        self.value = password


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
        password=None,
    ):
        if secondary is None:
            secondary = ["secondary"]
        self._password_object = (
            _Dummy(password)
            if password
            else Password(username=username, length=length, website=website, seed=seed)
        )

        self.cipher = AESCipher(master=master, salt=salt, secondary=secondary)
        self.hash = self.cipher.encrypt(self._password_object.value)
        self.website = website
        self.username = username

    def decrypt(self) -> str:
        """Decrypt the password"""
        return self.cipher.decrypt(self.hash)

    def __str__(self) -> str:
        return str(self.hash)

    def __len__(self) -> int:
        return len(self.hash)

    def __dict__(self):
        hashed = self.hash.decode().replace("b'", "").replace("'", "")
        username = self.username
        website = self.website
        return {"hash": hashed, "username": username, "website": website}
