from os import path
from pwdgen import Password
from encrypt import AESCipher
from securePassword import SecurePasword


def securePwdDemo():
    """"""
    username = "username"
    website = "site.com"
    seed = 10
    secondary = "a"
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
    print(decrypt(pwd.hash, getMaster(), secondary=secondary, salt=salt))


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


def tests():
    # TODO: update tests with checking if encryption works
    website_name = input("Website name: ")
    username = "test"
    seed = "seed"
    secondary = "secondary"
    for i in range(8, 550):
        size = i
        password = Password(
            length=size, username=username, website=website_name, seed=seed
        )
        pwd = SecurePasword(
            length=size,
            username=username,
            website=website_name,
            seed=seed,
            master=getMaster(),
        )
        cipher = AESCipher(master=getMaster(), secondary=secondary)
        encrypted = cipher.encrypt(password.value)

        if decrypt(encrypted, getMaster(), secondary=secondary) != password.value:
            print(f"{password.readable()} failed")
            break
        length = len(password)
        if length < size:
            print("Password is too short")
            debug(password, size)
            break
        if length > size:
            print("Password is too long")
            debug(password, size)
            break
        if password.value != pwd.decrypt():
            print("Passwords are not equal")
            print(type(password), type(pwd.decrypt()))
            debug(password, size)
            break
        try:
            if password.words[-1] not in password.value:
                print("Password fails to contain the last word")
                debug(password, size)
                break
        except IndexError:
            pass
        print(f"Password, {password.readable()}, is correct")


if __name__ == "__main__":
    # tests()
    # TODO: update tests with checking if encryption works
    print("TODO: update tests with checking if encryption works")
    # demo()
    securePwdDemo()
