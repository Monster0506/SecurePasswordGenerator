from signal import raise_signal
from securePassword import SecurePasword
from os import path



if path.exists(".env"):
    with open(".env") as f:
        master = f.readline()
else:
    raise FileNotFoundError("Master key not found")        


username = "test"


pwd = SecurePasword(username=username, seed=None, length=32, master=master)

def createSecurePassword(username, master="key", length=32, seed=None ):
    pwd = SecurePasword(username=username, seed=seed, length=length, master=master)
    return pwd

print(createSecurePassword(username=username, master=master, length=32, seed=None))