from securePassword import SecurePasword


def new(master, username, website, seed, length=32, secondary = ["secondary"], salt=b"insecure salt"):
    password = SecurePasword(master=master, username=username, website=website, seed=seed, length=length, secondary=secondary, salt=salt)
    return password

if __name__ == "__main__":
    with open(".env", "r") as file:
        master = file.readline()
    password = new(master=master, username="username", website="site.com", seed=["value", "test", "test"])
    print(password)
    print(password.decrypt())