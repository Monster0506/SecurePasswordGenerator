from API import (
    new,
    encrypt,
    decrypt,
    decrypt_file_by_username,
    decrypt_file_by_website,
    store,
    decrypt_file,
    set_global_master,
    DEFAULT_SALT,
    DEFAULT_SECONDARY,
    verify_fingerprint,
    Cipher,
)
from random import randint

filename = "test.json"
text_file = "test.txt"
global master
master = set_global_master(".env")


def gen_pwd_to_file():
    print("gen_pwd_to_file")
    password = new(
        master=master,
        username=str(randint(0, 100)),
        website="site.com",
        seed=["value", "test", "test"],
    )
    store(filename, password, write_non_exisiting=False)
    print(password.decrypt())


def gen_from_pwd_to_file():
    print("gen_from_pwd_to_file")
    password = new(
        master=master,
        username="Demo User",
        website="example.com",
        seed=["demo", "test", "example"],
        password="demo",
    )
    store(filename, password, write_non_exisiting=True)


def decrypt_file_test():
    print("decrypt_file_test")
    with open("test.txt", "w") as file:
        for password in decrypt_file(filename=filename, master=master):
            print(password)
            file.write(password + "\n")


def decrypt_test():
    print("decrypt_test")
    print(
        decrypt(
            encrypted="8S6sC1pR9YGl2Bv+rWTewHNNrC8LtH6NuSHg3MtOv44=",
            master=master,
            secondary=DEFAULT_SECONDARY,
            salt=DEFAULT_SALT,
        )
    )


def test_encrypt_decrypt():
    print("test_encrypt_decrypt")
    encrypted = encrypt(
        value="test",
        master=master,
        secondary=DEFAULT_SECONDARY,
        salt=DEFAULT_SALT,
    )
    print(encrypted)
    decrypted = decrypt(
        encrypted, master, secondary=DEFAULT_SECONDARY, salt=DEFAULT_SALT
    )
    print(decrypted)


def test_by_website_file():
    print("test_by_website")
    website = "example.com"
    values = decrypt_file_by_website(filename=filename, master=master, website=website)
    for value in values:
        print(value)


def test_by_username_file():
    print("test_by_username")
    username = "Demo User"
    values = decrypt_file_by_username(filename, username, master)
    for value in values:
        print(value)


def test_fingerprint():
    print("test_fingerprint")
    cipher = Cipher(master=master, salt=DEFAULT_SALT, secondary=DEFAULT_SECONDARY)
    value = verify_fingerprint(
            cipher,
            "77688998d801db988b7799aa42cc9d16d1d1ed29fbba5b3f697bdfdfec36727e",
        )
    print(value)


def test_fingerprint_fail():
    print("test_fingerprint_fail\nTHIS SHOULD BE FALSE")
    cipher = Cipher(master=master, salt=DEFAULT_SALT, secondary="failing")
    value = verify_fingerprint(
        cipher, "77688998d801db988b7799aa42cc9d16d1d1ed29fbba5b3f697bdfdfec36727e"
    )
    print(value)


def tests():
    test_encryption_decrytion()
    test_files()
    test_fingerprints()


def test_encryption_decrytion():
    decrypt_test()
    test_encrypt_decrypt()


def test_files():
    decrypt_file_test()
    gen_from_pwd_to_file()
    gen_pwd_to_file()
    test_by_username_file()
    test_by_website_file()


def test_fingerprints():
    test_fingerprint()
    test_fingerprint_fail()


if __name__ == "__main__":
    tests()
