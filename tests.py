from random import randint

from tjcrypt import *

filename = "test.json"
text_file = "test.txt"
fingerprint = "6d095023ddba833c5a0c6cc677aaefbbe44fc4f945ffdd554f1171ff7b6a9ede2f183a4e64493af3f377f745eda502363cd3e7ef6e4d266d444758de0a85fcc8"
hashed = "MKDA944FnPFsJAmMaweZj3Ap7GbTNjadHhjF62wcN3U="
master_file = "master.pem"
username = "Demo User"
website = "example.com"
global master
# write_master(master_file, master="master", passphrase="test", write_non_existing=True)
master = read_master(master_file, "test")


def gen_pwd_to_file():
    print("gen_pwd_to_file")
    password = new(
        master=master,
        username=str(randint(0, 100)),
        website="site.com",
        seed=["value", "test", "test"],
    )
    store(filename, password, write_non_existing=True)
    if dec := password.decrypt():
        print(dec)
        print("passing")
    else:
        print("failing")
        exit()


def gen_from_pwd_to_file():
    print("gen_from_pwd_to_file")
    password = new(
        master=master,
        username=username,
        website=website,
        seed=["demo", "test", "example"],
        password="demo",
    )
    if store(filename, password, write_non_existing=False):
        print("passing")
    else:
        print("failing")
        exit()


def decrypt_file_test():
    print("decrypt_file_test")
    with open("test.txt", "w") as file:
        for password in decrypt_file(filename=filename, master=master):
            if password:
                print(password)
                file.write(password + "\n")
                print("passing")
            else:
                print("failing")
                exit()


def decrypt_test():
    print("decrypt_test")
    decrypted = decrypt(
        encrypted=hashed,
        master=master,
        secondary=DEFAULT_SECONDARY,
        salt=DEFAULT_SALT,
    )
    if decrypted == "demo":
        print("passing")
    else:
        print("failing")
        exit()


def test_encrypt_decrypt():
    print("test_encrypt_decrypt")
    encrypted = encrypt(
        value="test",
        master=master,
        secondary=DEFAULT_SECONDARY,
        salt=DEFAULT_SALT,
    )
    if encrypted:
        print(encrypted)
        print("passing")
    else:
        print("failing")
        exit()
    decrypted = decrypt(
        encrypted, master, secondary=DEFAULT_SECONDARY, salt=DEFAULT_SALT
    )
    if decrypted == "test":
        print("passing")
    else:
        print("failing")


def test_by_website_file():
    print("test_by_website")
    values = decrypt_file_by_website(filename=filename, master=master, website=website)
    for value in values:
        if value:
            print(value)
            print("passing")
        else:
            print("failing")
            exit()


def test_by_username_file():
    print("test_by_username")
    values = decrypt_file_by_username(filename, username, master)
    for value in values:
        if value:
            print(value)
            print("passing")
        else:
            print("failing")
            exit()


def test_fingerprint():
    print("test_fingerprint")
    cipher = Cipher(master=master, salt=DEFAULT_SALT, secondary=DEFAULT_SECONDARY)
    value = verify_fingerprint(cipher, fingerprint)
    print("passing" if value else "failing")
    if not value:
        exit()


def test_fingerprint_fail():
    print("test_fingerprint_fail")
    cipher = Cipher(
        master=master,
        salt=DEFAULT_SALT,
        secondary=DEFAULT_SECONDARY,
        public="adskfasdf",
    )

    value = verify_fingerprint(cipher, fingerprint)
    print("failing" if value else "passing")
    if value:
        exit()
    cipher = Cipher(master=master, salt=DEFAULT_SALT, secondary="FAILING")
    print(cipher.fingerprint)
    value = verify_fingerprint(cipher, fingerprint)
    print("failing" if value else "passing")
    if value:
        exit()


def test_fingerprint_public():
    print("test_fingerprint_public")
    pwd = new(
        master=master,
        username=username,
        website="finger_print_public",
        seed=["demo", "test", "example"],
        password="demo",
        public="different public key",
    )
    store("test.json", pwd, write_non_existing=False)
    value = verify_fingerprint(pwd, fingerprint)
    print("failing" if value else "passing")
    if value:
        exit()


def test_fingerprint_words():
    print("test_fingerprint_words")
    value = verify_words_fingerprint(
        "uncertain impound drastic clothes sycamore swimming guru unnoticed",
        "07c1e3cafbe59e0055c306dc7321c29e155d1e187dacbb588d79854ba0be5f26758e42ebac8e79f4cc467fd6068283c247cd73a19bf025473a632140427b0bd5",
    )
    print("passing" if value else "failing")
    if not value:
        exit()


def main():
    test_files()
    test_encryption_decrytion()
    test_fingerprints()


def test_encryption_decrytion():
    decrypt_test()
    test_encrypt_decrypt()


def test_files():
    gen_pwd_to_file()
    gen_from_pwd_to_file()
    decrypt_file_test()
    test_by_username_file()
    test_by_website_file()


def test_fingerprints():
    test_fingerprint()
    test_fingerprint_fail()
    test_fingerprint_public()
    test_fingerprint_words()


if __name__ == "__main__":
    main()
