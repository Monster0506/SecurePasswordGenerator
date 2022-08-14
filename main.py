from os import path
from pwdgen import Password
from encrypt import AESCipher
from securePassword import SecurePasword


def securePwdDemo():
    """"""
    username = "username"
    website = "site.com"
    seed = 10
    length = 32
    gen_code = None
    pwd = SecurePasword(username=username,
                        website=website,
                        length=length,
                        master=getMaster(),
                        gen_code=gen_code,
                        seed=seed)
    password = str(pwd).removeprefix("b'")
    password = password.removesuffix("'")
    print(password)
    print(pwd.decrypt())

    # pwd2 = 'KHdK+5szRE39TZw8hX3WwtvnW+sphW8EA8ZL8RGUoG/+ow1toENJQetJcV/qCdc\
    #     D451csPeu4juIK6bNIowhPA=='
    # print(decrypt(pwd2, getMaster(), username))

    # print(decrypt(password, getMaster(), username))
    # print(decrypt(password, "test", username))

    # pwd0 = Password(username=username,
    #                 website=website,
    #                 length=length,
    #                 private_key=private_key)
    # print(pwd0.readable())


def getMaster(filename=".env"):
    if path.exists(filename):
        with open(filename, "r") as file:
            master = file.readline()
    else:
        raise FileNotFoundError("Master key not found")
    return master


def debug(password, size):
    length = len(password)
    print(f"Attempted length: {size}")
    print(f"READABLE: {password.readable()}")
    print(f"Length: {length}")
    print(f"Words: {password.words}")
    print(f"Value: {password.value}")


def decrypt(encrypted, master, username):
    cipher = AESCipher(master=master, salt=username)
    return cipher.decrypt(encrypted)


def tests():
    website_name = input("Website name: ")
    username = "test"
    seed = 10
    gen_code = 100
    for i in range(8, 1250):
        size = i
        password = Password(username=username,
                            length=size,
                            website=website_name,
                            seed=seed,
                            gen_code=gen_code)
        pwd = SecurePasword(
            gen_code=gen_code,
            seed=seed,
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
    tests()
    securePwdDemo()
