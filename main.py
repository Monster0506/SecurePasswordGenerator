TESTING = False
DEMO = False
SECUREDEMO = False
from os import path
from pwdgen import Password
from encrypt import AESCipher
from securePassword import SecurePasword


def securePwdDemo():
    """"""
    username = "username"
    website = "site.com"
    seed = ["value", "tesst", "test"]
    secondary = ["test", "value"]
    salt = "salt"
    length = 32
    pwd = SecurePasword(
        seed=seed,
        master=getMaster(),
        username=username,
        website=website,
        length=length,
        secondary=secondary,
        salt=salt,
    )

    hashed = str(pwd).removeprefix("b'")
    hashed = hashed.removesuffix("'")
    print(hashed)
    print(pwd.decrypt())
    # print(decrypt(pwd.hash, getMaster(), secondary=secondary, salt=salt))


def getMaster(filename=".env"):
    if path.exists(filename):
        with open(filename, "r") as file:
            master = file.readline()
    else:
        raise FileNotFoundError("Master key not found")
    return master


def demo():
    website_name = input("Website name: ")
    user_name = "TEST"
    password = Password(
        length=32, username=user_name, website=website_name, seed="test"
    )
    master = getMaster()
    cipher = AESCipher(master, user_name)
    encrypted = cipher.encrypt(password)
    decrypted = cipher.decrypt(encrypted)
    print(f"Password: {password}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    pwd = SecurePasword(
        username=user_name, website=website_name, length=32, master=master, seed="test"
    )

    print(f"Encrypted: {pwd}")
    print(f"Decrypted: {pwd.decrypt()}")
    # print(f"Decrypted: {decrypt(pwd.hash, master=master, username=user_name)}")


def debug(password, size):
    length = len(password)
    print(f"Attempted length: {size}")
    print(f"READABLE: {password.readable()}")
    print(f"Length: {length}")
    print(f"Words: {password.words}")
    print(f"Value: {password.value}")


def decrypt(encrypted, master, secondary="", salt=b"insecure salt"):
    cipher = AESCipher(master=master, secondary=secondary, salt=salt)
    return cipher.decrypt(encrypted)


def test_secondary(pwd, password, size):
    try:
        if (
            AESCipher(master=getMaster(), secondary="FakeSecondary").decrypt(pwd.hash)
            == password.value
        ):
            print("Secondary key failed to prevent decryption")
            return True
    except UnicodeDecodeError:
        pass
    try:
        if decrypt(pwd.hash, getMaster(), secondary="badSecondary") == password.value:
            print(f"Encryption with a secondary failed for {password.readable()}")
            print("Secondary has no effect")
            debug(password, size)
            print(
                f"Decrypted: {decrypt(pwd.hash, getMaster(), secondary='badSecondary')}"
            )
            print(pwd.hash)
            return True
    except UnicodeDecodeError:
        pass
    return False


def test_length(size, length, password):
    if length < size:
        print("Password is too short")
        debug(password, size)
        return True
    if length > size:
        print("Password is too long")
        debug(password, size)
        return True
    return False


def test_decryption(decrypted, password, size, pwd, encrypted, secondary):
    if decrypted != password.value:
        print(f"Decryption failed for {size}")
        debug(password, size)
        print(f"Decrypted: {decrypted}")
        print(f"Encrypted: {encrypted}")
        return True
    if decrypt(encrypted, getMaster(), secondary=secondary) != password.value:
        print(f"{password.readable()} failed to be decrypted properly")
        debug(password, size)
        print(pwd.decrypt())
        return True
    if password.value != pwd.decrypt():
        print("Passwords are not equal")
        print(type(password), type(pwd.decrypt()))
        debug(password, size)
        return True
    if password.value != decrypted:
        print(f"{password.readable()} failed to be decrypted properly")
        debug(password, size)
        print(decrypted)
        return True
    return False


def test_generation(password, size):
    try:
        if password.words[-1] not in password.value:
            print("Password fails to contain the last word")
            debug(password, size)
            return True
    except IndexError:
        pass
    for word in password.words:
        if word not in password.value:
            print(f"Password fails to contain {word}")
            debug(password, size)
            return True
    return False


def test_encryption(password, size, pwd, encrypted, secondary, decrypted):
    if encrypted == pwd.hash:
        print(
            f"{password.readable()} hash failed to be encrypted with a different hash"
        )
        return True
    try:
        if (
            AESCipher(master="FakeMaster", secondary=secondary).decrypt(pwd.hash)
            == password.value
        ):
            print(f"Master key failed to prevent decryption")
            debug(password, size)
            print(decrypted)
            print(AESCipher(master="FakeMaster", secondary=secondary).decrypt(pwd.hash))
            return True
    except UnicodeDecodeError:
        pass


def tests():
    website_name = input("Website name: ")
    username = "test"
    seed = "seed"
    secondary = "secondary"
    cipher = AESCipher(master=getMaster(), secondary=secondary)
    for i in range(8, 1250):
        size = i
        password = Password(
            length=size, username=username, website=website_name, seed=seed
        )
        pwd = SecurePasword(
            length=size,
            username=username,
            website=website_name,
            seed=seed,
            secondary=secondary,
            master=getMaster(),
        )
        encrypted = cipher.encrypt(password.value)
        decrypted = decrypt(pwd.hash, getMaster(), secondary=secondary)
        length = len(password)
        if test_secondary(pwd, password, size):
            break
        if test_length(size, length, password):
            break
        if test_decryption(decrypted, password, size, pwd, encrypted, secondary):
            break
        if test_generation(password, size):
            break
        if test_encryption(password, size, pwd, encrypted, secondary, decrypted):
            break
        print(f"Password and encryption are correct")


if __name__ == "__main__":
    if TESTING:
        tests()
    if DEMO:
        demo()
    if SECUREDEMO:
        securePwdDemo()
