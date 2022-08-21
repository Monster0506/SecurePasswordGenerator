from hashlib import sha256
from os import path

try:
    import simplejson as json  # type: ignore
except ImportError:
    import json

from Crypto.IO import PEM
from Crypto.Util.py3compat import tobytes, tostr

from securePassword import Cipher, SecurePasword

# this is the default salt value used for encryption. This can be changed to any value.
# Please, please, please, do not use this, as it is insecure and can be easily cracked.
DEFAULT_SALT = b"insecure salt"

# this is the default secondary value used for encryption. This can be changed to any value.
# Please, please, please, do not use this, as it is insecure and can be easily cracked.
DEFAULT_SECONDARY = ["secondary"]


def verify_fingerprint(cipher: SecurePasword, fingerprint: str):
    """Verify that a cipher has the same fingerprint as the one provided.

    Args:
        cipher (SecurePasword): The cipher to verify
        fingerprint (str): The fingerprint to verify against

    Returns:
        bool: Whether the cipher has the same fingerprint as the one provided.
    """
    return cipher.verify_fingerprint(fingerprint)


def write_master(filename: str = "master.pem", master: str = "master", passphrase=None):
    """Write a master key to a file using PEM format.

    Format:
    ----- BEGIN MASTER KEY -----
    <master key>
    ----- END MASTER KEY -----

    Args:
        filename (str, optional): the file to write to. Preferably a .pem . Defaults to "master.pem".
        master (str, optional): the plaintext master key. Defaults to "master".
        passphrase (str, optional): the phrase to unlock the master key. Defaults to None.
    """
    master = sha256(master.encode()).digest()
    if passphrase is not None:
        passphrase = tobytes(passphrase)
    write = _write_master(master, passphrase)
    with open(filename, "w") as file:
        file.write(write)


def _write_master(master, passphrase):
    if passphrase is not None:
        passphrase = tobytes(passphrase)
    master = tobytes(master)
    return PEM.encode(master, "MASTER KEY", passphrase)


def read_master(filename: str, passphrase: str = None):
    """Set the master key for a .pem file created with write_master.

    Args:
        filename (str): The name of the file to read from.
    """
    if passphrase is not None:
        passphrase = tobytes(passphrase)
    with open(filename, "r") as file:
        data = PEM.decode(file.read(), passphrase)
    # note, data is a bytes object, and we want a string
    return tostr(data[0])


def encrypt(value, master, secondary=DEFAULT_SECONDARY, salt=DEFAULT_SALT):
    """Encrypt a value.

    Args:
        value (any): The value to encrypt
        master (any): The master key to use for encryption
        secondary (list, optional): The secondary keys to use for encryption. Defaults to DEFAULT_SECONDARY.
        salt (bytes, optional): The salt to use for encryption. Defaults to DEFAULT_SALT.

    Returns:
        str: The encrypted value
    """
    cipher = Cipher(master=master, salt=salt, secondary=secondary)
    return cipher.encrypt(value)


def new(
    master,  # master key
    username: str,
    website: str,
    seed,
    length: int = 32,
    secondary=DEFAULT_SECONDARY,
    salt=DEFAULT_SALT,
    password=None,
    public="anonymous",
):
    """This is a constructor for SecurePasword

    Args:
        master (any): The master key to use for encryption
        username (str): The username. Used for generating the password
        website (str): The website. Used for generating the password. Can be anything, if consistent.
        seed (Iterable | str | list): The seed to use. Used for generating different passwords with the same username. An iterable of any type.
        length (int, optional): The length of the password. Defaults to 32.
        secondary (Iterable | str | list, optional): Additional encryption values to prevent bruteforcing master. Defaults to DEFAULT_SECONDARY. An iterable of any type.
        salt (bytes, optional): The salt for the password. Defaults to DEFAULT_SALT.
        password (str | bytes | None, optional): If None, generates a secure password. Else, this is the password to be encrypted. Defaults to None.
        public (str, optional): The public key to use for encryption. Defaults to "public".

    Returns:
        SecurePassword: The SecurePassword object, represented as a hash.
    """
    password = SecurePasword(
        master=master,
        username=username,
        website=website,
        seed=seed,
        length=length,
        secondary=secondary,
        salt=salt,
        password=password,
        public=public,
    )
    return password


def _write(filename: str, password: SecurePasword):
    with open(filename, "r") as file:
        data = json.load(file)
    data.append(password._store())
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)


def store(filename: str, password: SecurePasword, write_non_exisiting=False):
    """Store a password object in a file.

    Notes:
        Uses json formatting.

    Args:
        filename (str): The file to store the password in
        password (SecurePasword): The password object to store
        write_non_exisiting (bool, optional): If to ignore a non-existant file and create it. Defaults to False.

    Raises:
        FileNotFoundError: if write_non_exisiting is False and the file does not exist.
            Format: "File: {filename} not found"
    """
    if write_non_exisiting:
        if not path.exists(filename):
            with open(filename, "w") as file:
                json.dump([], file)
        _write(filename, password)
        return
    if path.exists(filename):
        _write(filename, password)
        return
    raise FileNotFoundError(f"File: {filename} not found")


def decrypt_file_by_website(
    filename: str,
    website: str,
    master,
    secondary: list = DEFAULT_SECONDARY,
    salt=DEFAULT_SALT,
):
    """Decrypt every password in a file that matches the website.

    Args:
        filename (str): The filename to decrypt
        website (str): The string to match against the website key
        master (any): The master key to use for decryption
        secondary (list | string | Iterable, optional): The secondary key used for decryption. Defaults to DEFAULT_SECONDARY.
        salt (list | string | Iterable, optional): The salt value used for encryption. Defaults to DEFAULT_SALT.

    Yields:
        string, username: the decrypted password and the username
    """
    for dictionary in json.load(open(filename)):
        if dictionary["website"] == website:
            yield decrypt(dictionary["hash"], master, secondary, salt), dictionary[
                "username"
            ]


def decrypt_file(
    filename: str, master, secondary: list = DEFAULT_SECONDARY, salt=DEFAULT_SALT
):
    """Decrypt an entire json file stored with store()

    Args:
        filename (str): The name of the file to decrypt
        master (any): The master key that was used to encrypt the hashes
        secondary (list, optional): The secondary keys used to encrypt the hashes. Defaults to DEFAULT_SECONDARY.
        salt (bytes, optional): The salt used to salt the encrypted hashes. Defaults to DEFAULT_SALT.

    Yields:
        str: The decrypted passwords
    """
    for dictionary in json.load(open(filename)):
        yield decrypt(dictionary["hash"], master, secondary, salt)


def decrypt_file_by_username(
    filename: str,
    username: str,
    master,
    secondary: list = DEFAULT_SECONDARY,
    salt=DEFAULT_SALT,
):
    """Decrypt every password in a file that matches the username.

    Args:
        filename (str): The filename to decrypt
        username (str): The string to match against the username key
        master (any): the master key to use for decryption
        secondary (list | str | Iterable, optional): The secondary key the password was encrypted with. Defaults to DEFAULT_SECONDARY.
        salt (list | str | Iterable, optional): The salt values used to encrypt the password. Defaults to DEFAULT_SALT.

    Yields:
        string, string: The decrypted password and the username
    """
    for dictionary in json.load(open(filename)):
        if dictionary["username"] == username:
            yield decrypt(dictionary["hash"], master, secondary, salt), dictionary[
                "website"
            ]


def decrypt(encrypted, master, secondary=DEFAULT_SECONDARY, salt=DEFAULT_SALT):
    """Decrypt a encrypted hash.

    Args:
        encrypted (str): The encrypted hash
        master (any): The master key that was used to encrypt the hash
        secondary (list, optional): The secondary keys used to encrypt the hash. Defaults to DEFAULT_SECONDARY.
        salt (bytes, optional): The salt used to salt the encrypted hash. Defaults to DEFAULT_SALT.

    Returns:
        any: The decrypted value
    """
    cipher = Cipher(master=master, salt=salt, secondary=secondary)
    return cipher.decrypt(encrypted)
