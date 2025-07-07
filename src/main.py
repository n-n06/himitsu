import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

load_dotenv()




def main():

    password = b"password"
    salt_b64 = os.environ.get("SALT")


    if salt_b64 is None:
        raise ValueError("No salt provided in .env variables")


    salt = base64.urlsafe_b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.encrypt(b"Secret message!")
    f.decrypt(token)
