# TODO: Add chacha cipher.
# TODO: chacha ==> Use key, nonce, and block number to produce an encrpyted ("random") string (Currently implemented.) -> bytes -(xor message)> output
# TODO: decrypt ==> produce string as above -(xor ciphertext)> message
""" Encrypt a plaintext, and decrypt it """
from base64 import b64decode, b64encode
from hashlib import sha256

import requests
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.py3compat import tobytes, tostr


class Cipher(object):
    """A securely encrypted AES cipher.

    PLEASE USE THE API INSTEAD OF THIS CLASS

    Args:
        master: The master key to use for encryption
        salt: The salt to use for encryption
        secondary: Secondary keys for additional encryption
        public: public signing key for verifying the encryption

    Implements:
        encrypt: Encrypt a value with the master key, secondary keys, and salt
        decrypt: Decrypt a value
        _pad: Pad a string to 16 bytes
        _unpad: Unpad a string to 16 bytes
        verify_fingerprint: Verify the fingerprint of the encryption is the same as the one provided.
        _generate_words: Generate a list of words from a fingerprint

    values:
        block_size: The block size of the cipher
        public: The public signing key for verifying the encryption.
        key: The key for the cipher.
        fingerprint: The fingerprint of the cipher. Can be used to verify the encryption.
        words: The list of words from the fingerprint, for simple sharing.
    """

    def __init__(self, master, salt=None, secondary=None, public="anonymous"):
        master = tobytes(master)
        if secondary is None:
            secondary = ["secondary"]
        if salt is None:
            salt = Random.new().read(AES.block_size)
        else:
            salts = ""
            for item in salts:
                item = tobytes(item)
                item = sha256(item).digest()
                salts += item
            salt = tobytes(salts)
        secondaries = "".join(sha256(tobytes(key)).hexdigest() for key in secondary)
        secondaries = sha256(tobytes(secondaries)).hexdigest().encode()
        salt = tobytes(salt)
        master_key = PBKDF2(master, salt, 32)
        salt_value = PBKDF2(salt, master_key, 32)
        self.block_size = AES.block_size
        kdf = PBKDF2(
            str(sha256(master_key + secondaries).hexdigest()), salt_value, 32, 1000
        )

        self.public = str(sha256(public.encode()).hexdigest())
        fingerprint = (
            str(
                sha256(
                    tobytes(sha256(salt_value + master_key + secondaries).hexdigest())
                ).hexdigest()
            )
            + self.public
        )

        self.fingerprint = fingerprint
        self.words = self._generate_words(fingerprint)
        self.key = kdf[:32]
        self.signature = sha256(self.key).digest()

    def encrypt(self, raw) -> bytes:
        """Encrypt a value with the master key, secondary keys, and salt

        Args:
            raw (any [plaintext]): The value to encrypt

        Returns:
            bytes: The encrypted value
        """
        raw = self._pad(raw)
        raw = tobytes(raw)
        init_vector = Random.new().read(AES.block_size)
        cypher = AES.new(self.key, AES.MODE_GCM, init_vector)
        return b64encode(init_vector + cypher.encrypt(raw))

    def decrypt(self, enc) -> str:
        """Decrypt a value with the master key, secondary keys, and salt

        Args:
            enc (binary str): The value to decrypt

        Returns:
            str: the decrypted value
        """
        enc = b64decode(enc)
        # enc = tostr(enc)
        init_vector = enc[: self.block_size]
        cipher = AES.new(self.key, AES.MODE_GCM, init_vector)
        return self._unpad(cipher.decrypt(enc[self.block_size :]))

    def _pad(self, string: str) -> str:
        """Pad a string to 16 bytes

        Args:
            string (str): string to be padded

        Returns:
            str: the padded string
        """
        return string + (self.block_size - len(string) % self.block_size) * chr(
            self.block_size - len(string) % self.block_size
        )

    @staticmethod
    def _unpad(string):
        """Unpad a string from 16 bytes

        Args:
            string (str): string to be unpadded

        Returns:
            str: unpadded string
        """
        return tostr(
            string[: -ord(string[len(string) - 1 :])]
        )  # sourcery skip: simplify-negative-index

    def verify_fingerprint(self, fingerprint: str) -> bool:
        """Determine if the ciphers' are the same.

        Args:
            fingerprint (str): the fingerprint of the other cipher

        Returns:
            bool: True if the fingerprints are the same, False otherwise
        """
        return self.fingerprint == fingerprint

    @staticmethod
    def _generate_words(fingerprint: str):
        fingerprint = sha256(tobytes(fingerprint)).hexdigest()
        item = requests.get(
            "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt"
        )
        words = []
        indicies = []

        # divide the fingerprint into chunks of 8 bits
        for i in range(0, len(fingerprint), 8):
            index = fingerprint[i : i + 8]
            index = int(index, 16)
            indicies.append(index)

        for index in indicies:
            word = item.text.splitlines()[index % len(item.text.splitlines())]
            word = word[word.find("\t") :]
            word = word.removeprefix("\t")
            words.append(word)
        return " ".join(words)
