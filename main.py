from os import path
from pwdGen import Password
from encrypt import AESCipher
from securePassword import SecurePasword


def securePwdDemo():
    username = "tjraklovits@gmail.com"
    website = "google.com"
    seed = 11
    # seed = None
    length = 32
    pwd = SecurePasword(
        username=username, website=website, length=length, master=getMaster(), seed=seed
    )
    password = str(pwd).removeprefix("b'")
    password = password.removesuffix("'")
    print(password)
    print(pwd.decrypt())

    # print(decrypt(password, getMaster(), username))
    # pwd0 = Password(username=username, website=website, length=length, seed=seed)
    # print(pwd0.readable())


def getMaster(filename=".env"):
    if path.exists(filename):
        with open(filename, "r") as f:
            master = f.readline()
    else:
        raise FileNotFoundError("Master key not found")
    return master


def demo():
    website_name = input("Website name: ")
    user_name = "TEST"
    password = Password(length=32, username=user_name, website=website_name)
    master = getMaster()
    cipher = AESCipher(master, user_name)
    encrypted = cipher.encrypt(password)
    decrypted = cipher.decrypt(encrypted)
    print(f"Password: {password}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    pwd = SecurePasword(
        username=user_name, website=website_name, length=32, master=master
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


def decrypt(encrypted, master, username):
    cipher = AESCipher(master, username)
    return cipher.decrypt(encrypted)


def tests():
    website_name = input("Website name: ")
    username = "test"
    for i in range(8, 1250):
        size = i
        password = Password(username=username, length=size, website=website_name)
        pwd = SecurePasword(
            username=username,
            website=website_name,
            length=size,
            master=getMaster(),
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
    # demo()
    securePwdDemo()
