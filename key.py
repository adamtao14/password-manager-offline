from cryptography.fernet import Fernet
import os, pyzipper
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

def generate_key():
   return Fernet.generate_key()

def initialize_cipher(key):
   return Fernet(key)

def encrypt_password(cipher, password):
   return cipher.encrypt(password.encode()).decode()

def decrypt_password(cipher, encrypted_password):
   return cipher.decrypt(encrypted_password.encode()).decode()

def key_exists():
    return os.path.isfile(os.getenv('ZIP_NAME'))

def delete_key():
    if key_exists():
        os.remove(os.getenv('ZIP_NAME'))


def derive_key_from_password(password, salt=b'i8u2387yrefh9pga', iterations=100_000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def save_key(encryption_key, master_password):
    with pyzipper.AESZipFile(os.getenv('ZIP_NAME'),'w',compression=pyzipper.ZIP_LZMA,encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(master_password.encode('utf-8'))
        zf.writestr(os.getenv('KEY_NAME'), encryption_key)


def read_key_from_zip(master_password):
    with pyzipper.AESZipFile(os.getenv('ZIP_NAME')) as zf:
        zf.setpassword(master_password.encode('utf-8'))
        encryption_key = zf.read(os.getenv('KEY_NAME'))
    
    return encryption_key

