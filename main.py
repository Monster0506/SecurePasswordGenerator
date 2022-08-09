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




def demo():
    websiteName = input("Website name: ")
    password = Password(32, seed = websiteName)
    master = getMaster()
    cipher = AESCipher(master)
    encrypted = cipher.encrypt(password)
    decrypted = cipher.decrypt(encrypted)
    print(f"Password: {password}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    pwd = SecurePasword(32, websiteName, master=getMaster())
    print(f"Encrypted: {pwd}")
    print(f"Decrypted: {pwd.decrypt()}")



def debug(password, size):
    length = len(password)
    print(f"Attempted length: {size}")
    print(f"READABLE: {password.readable()}")
    print(f"Length: {length}")
    print(f"Words: {password.words}")
    print(f"Value: {password.value}")


def tests():
    for i in range(8, 5000):
        size = i
        password = Password(size)
        length = len(password)
        if length < size:
            print("Password is too short")
            debug(password, size)
            break
        elif length > size:
            print("Password is too long")
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


if __name__ == "__main__":
    # tests()
    demo()
