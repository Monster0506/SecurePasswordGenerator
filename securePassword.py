from encrypt import Cipher
from password import GenPassword


class _Dummy(object):
    """This is a dummy class to represent a password.
    Please do not use this class
    """

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
        public="public",
    ):
        if secondary is None:
            secondary = ["secondary"]
        self._password_object = (
            _Dummy(password)
            if password
            else GenPassword(username=username, length=length, website=website, seed=seed)
        )

        self.cipher = Cipher(
            master=master, salt=salt, secondary=secondary, public=public
        )
        self.hash = self.cipher.encrypt(self._password_object.value)
        self.website = website
        self.username = username
        self.fingerprint = self.cipher.fingerprint

    def decrypt(self) -> str:
        """Decrypt the password"""
        return self.cipher.decrypt(self.hash)

    def __str__(self) -> str:
        return str(self.hash)

    def __len__(self) -> int:
        return len(self.hash)

    def _store(self):
        hashed = self.hash.decode().replace("b'", "").replace("'", "")
        username = self.username
        website = self.website
        fingerprint = self.fingerprint
        fpwords = self.cipher.words
        return {
            "hash": hashed,
            "username": username,
            "website": website,
            "fingerprint": fingerprint,
            "words": fpwords,
        }

    def verify_fingerprint(self, fingerprint):
        return self.fingerprint == fingerprint
