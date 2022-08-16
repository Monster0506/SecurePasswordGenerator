from os import path
try:
    import simplejson as json # type: ignore
except ImportError:
    import json
from securePassword import SecurePasword
from securePassword import AESCipher


# testing flags. Ignore these
__DEBUG = False
__GEN_TO_FILE_TEST = False
__DECRYPT_FROM_FILE_TEST = False
__DECRYPT_TEST = False
__GEN_FROM_PASSWORD_TEST = True

# this is the default salt value used for encryption. This can be changed to any value.
# Please, please, please, do not use this, as it is insecure and can be easily cracked.
DEFAULT_SALT = b"insecure salt"

# this is the default secondary value used for encryption. This can be changed to any value.
# Please, please, please, do not use this, as it is insecure and can be easily cracked.
DEFAULT_SECONDARY = ["secondary"]

def new(
    master,
    username: str,
    website: str,
    seed,
    length: int = 32,
    secondary=DEFAULT_SECONDARY,
    salt=DEFAULT_SALT,
    password=None,
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
    )
    return password


def _write(filename, password):
    """The internal function for writing to a file"""
    with open(filename, "r") as file:
        data = json.load(file)
    data.append(password.__dict__())
    with open(filename, "w") as file:
        json.dump(data, file)


def store(filename: str, password: SecurePasword, write_non_exisiting=False):
    """Store a password object in a file.

    Notes:
        Uses json formatting.

    Args:
        filename (str): The file to store the password in
        password (SecurePasword): The password object to store
        write_non_exisiting (bool, optional): If to ignore a non-existant file and create it.. Defaults to False.

    Raises:
        FileNotFoundError: if write_non_exisiting is False and the file does not exist.
            "File: {filename} not found"
    """
    if write_non_exisiting:
        if path.exists(filename):
            _write(filename, password)
            return
        else:
            with open(filename, "w") as file:
                json.dump([], file)
                return
    if path.exists(filename):
        _write(filename, password)
        return
    raise FileNotFoundError("File: {} not found".format(filename))


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
        cipher = AESCipher(master=master, salt=salt, secondary=secondary)
        yield cipher.decrypt(dictionary["hash"])


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
    cipher = AESCipher(master=master, salt=salt, secondary=secondary)
    return cipher.decrypt(encrypted)


if __name__ == "__main__":
    with open(".env", "r") as file:
        master = file.readline()
    filename = "test.json"
    if __DEBUG:
        if __GEN_TO_FILE_TEST:
            password = new(
                master=master,
                username="username",
                website="site.com",
                seed=["value", "test", "test"],
            )
            store(filename, password, write_non_exisiting=False)
            print(password.decrypt())
        if __GEN_FROM_PASSWORD_TEST:
            password = new(
                master=master,
                username="Demo User",
                website="example.com",
                seed=["demo", "test", "example"],
                password="demo",
            )
            store(filename, password, write_non_exisiting=True)
        if __DECRYPT_FROM_FILE_TEST:
            for password in decrypt_file(filename=filename, master=master):
                with open("test.txt", "a") as file:
                    print(password)
                    file.write(password + "\n")
        if __DECRYPT_TEST:
            print(
                decrypt(
                    encrypted="8S6sC1pR9YGl2Bv+rWTewHNNrC8LtH6NuSHg3MtOv44=",
                    master=master,
                    secondary=DEFAULT_SECONDARY,
                    salt=b"insecure salt",
                )
            )
