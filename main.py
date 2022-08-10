"""The goal of this program is to generate a random password, with an optional seed, that uses numbers and pronounceable sounds
"""
from os import path
from pwdGen import Password
from encrypt import AESCipher
from securePassword import SecurePasword


def getMaster(filename=".env"):
    if path.exists(filename):
        with open(filename, "r") as f:
            master = f.readline()
    else:
        raise FileNotFoundError("Master key not found")
    return master


def decrypt(encrypted, master=getMaster(), username="username"):
    cipher = AESCipher(master, username)
    return cipher.decrypt(encrypted)


def demo():
    website_name = input("Website name: ")
    user_name = "TEST"
    password = Password(length=32, username=user_name, seed=website_name)
    master = getMaster()
    cipher = AESCipher(master)
    encrypted = cipher.encrypt(password)
    decrypted = cipher.decrypt(encrypted)
    print(f"Password: {password}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    pwd = SecurePasword(
        length=32, seed=website_name, master=getMaster(), username=user_name
    )

    print(f"Encrypted: {pwd}")
    print(f"Decrypted: {pwd.decrypt()}")
    print(f"Decrypted: {decrypt(pwd.hash, master=master, username=user_name)}")
    print(f"Decrypted FAIL: {decrypt(pwd.hash, master='test', username=user_name)}")
    print(f"Decrypted FAIL: {decrypt(pwd.hash, master=master, username='test')}")


def debug(password, size):
    length = len(password)
    print(f"Attempted length: {size}")
    print(f"READABLE: {password.readable()}")
    print(f"Length: {length}")
    print(f"Words: {password.words}")
    print(f"Value: {password.value}")


def tests():
    website_name = input("Website name: ")
    for i in range(8, 1250):
        size = i
        password = Password(length=size, username="test", seed=website_name)
        pwd = SecurePasword(
            length=size, username="test", seed=website_name, master=getMaster()
        )
        length = len(password)
        if length < size:
            print("Password is too short")
            debug(password, size)
            break
        elif length > size:
            print("Password is too long")
            debug(password, size)
            break
        elif password.value != pwd.decrypt():
            print("Passwords are not equal")
            print(type(password), type(pwd.decrypt()))
            debug(password, size)
            break
        else:
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
    demo()
