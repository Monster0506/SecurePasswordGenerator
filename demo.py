import json

import tjcrypt

# set some simple variables
master_file = "master_key.pem"
password_file = "passwords.json"

# generate a new master key. This can be random, by not providing the 'master' field, or a specific plaintext password intead.
# random password example:
# tjcrypt.write_master(master_file, passphrase="test") -> Exkd+49MTOVwmfJah2cD5DqCAbyCgrX46+DAF32Y7SmTtGJyM+a4i2Xmw732SdmZMwYV7zZfSjXKul+Rum99DJ0mfXE/qFFs
try:
    tjcrypt.write_master(master_file, passphrase="password", master="master")
except FileNotFoundError:
    print("File not found. Creating a new one.")
    tjcrypt.write_master(
        master_file, passphrase="password", write_non_existing=True, master="master"
    )
with open(master_file, "r") as f:
    # the file looks like this.
    # this is clearly encrypted. This is essentially a private key.
    print(f.read())

# read the master key from the file
master_key = tjcrypt.read_master(master_file, passphrase="password")
seed = [
    "this is one seed",
    "this is another seed",
    "there can be any number of seeds",
    "This is important, so that a different password is generated each time",
]
salt = [
    "This is a salt",
    "The default salt is bin('insecure salt')",
    "That is not very secure",
]


password0 = tjcrypt.new(
    master=master_key,
    username="username",
    website="example.com",
    seed=seed,
    salt=salt,
    public="The default public key is 'anonymous'",
    # You can optionally provide specific password, if you just want the tools from the library
    # password="password",
)


# this must be a json file and the SecurePassword object
# currently, the library only supports json files
try:
    tjcrypt.store(password_file, password0)
except FileNotFoundError:
    print("File not found. Creating a new one.")
    tjcrypt.store(password_file, password0, write_non_existing=True)
with open(password_file, "r") as file:
    data = json.loads(file.read())


# This file contains different objects.
for dictionary in enumerate(data):
    dicti = dictionary[1]
    print("\n")
    print("Password:", dictionary[0] + 1)
    # Firstly, the password encrypted with the master key, and any secondary keys and salts
    print(f"Hash: {dicti['hash']}")
    # this can be decrypted with the master key to get the password
    print(
        f"""Decrypted password: 
{tjcrypt.decrypt(dicti['hash'], master_key, salt=salt)}"""
    )
    # This also contains the username and website
    print("Username:", dicti["username"], "\nWebsite:", dicti["website"])
    # there is also a fingerprint. This fingerprint is two values cocatenated together to make a 128 character string
    # the first value is a 64 character hex string.add()
    # this represents the values used to generate the cipher, but you cannot use this to decrypt the password
    # the second value is also a 64 character hex string.
    # this is the hashed public key. You can uses this to verify the sender of a message.
    print("Fingerprint:", dicti["fingerprint"])
    print(f"Cipher fingerprint: {dicti['fingerprint'][:64]}")
    # notice, if the public key is not provided, the library will use the default public key, 'anonymous', hashed
    print(f"Public key: {dicti['fingerprint'][64:]}")
    # in order to easily share these fingerprints and compare ciphers and public keys, there is also a simple list of words
    print(f"Words: {dicti['words']}")
    # you can use this to verify the sender of a message is the owner of a cipher.
    print(
        f"Verify: {tjcrypt.verify_words_fingerprint(dicti['words'], dicti['fingerprint'])}"
    )

print("\n")
# also, if the fingerprint and the wordslist do not match, the library will return false
print(
    f'Verify incorrect fingerprint: {tjcrypt.verify_words_fingerprint(data[0]["words"], "wowthisisalongandincorrectfingerprintitisuseless")}'
)
# if false was returned here, the fingerprint is working correctly


# you can also decrypt an entire file by using the decrypt_file function
decrypted = tjcrypt.decrypt_file(password_file, master_key, salt=salt)
# note, this returns a generator object. You can iterate over this to get the decrypted passwords
print("\n")
for password in decrypted:
    print(password)

# you can decrypt a file by username or website
# both of these functions return a tuple of the password, and the other value, which is the opposite of what was provided
decrypted_username = tjcrypt.decrypt_file_by_username(
    password_file, username="username", master=master_key, salt=salt
)
print("\n")
for password in decrypted_username:
    print(password)
decrypted_website = tjcrypt.decrypt_file_by_website(
    password_file, website="example.com", master=master_key, salt=salt
)
print("\n")
for password in decrypted_website:
    print(password)

# you can also compute the words from the fingerprint
print("\n")
print(tjcrypt.words_from_fingerprint(data[0]["fingerprint"]))

# you can also encrypt and decrypt a plaintext string with this module
# The downside of this is that it does not come with the benefits of the classes demonstrated above
encrypted = tjcrypt.encrypt(
    "secret message", master_key, salt=salt, secondary="secondary"
)
print(encrypted)
decrypted = tjcrypt.decrypt(encrypted, master_key, salt=salt, secondary="secondary")
print(decrypted)

# in order to have methods like fingerprint, you can use the Cipher class
encrypted_cipher = tjcrypt.Cipher(master_key, salt=salt, secondary="secondary")

print(encrypted_cipher.fingerprint)
print(encrypted_cipher.encrypt("secret message"))
print(encrypted_cipher.words)
print(tjcrypt.verify_words_fingerprint(encrypted_cipher.words, encrypted_cipher.fingerprint))
