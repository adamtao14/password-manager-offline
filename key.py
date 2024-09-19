from cryptography.fernet import Fernet
import os, pyzipper,secrets,base64,string,random
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def generate_key():
   return Fernet.generate_key()

def generate_recovery_key():
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(32))

def initialize_cipher(key):
   return Fernet(key)

def encrypt_password(cipher, password):
   return cipher.encrypt(password.encode()).decode()

def decrypt_password(cipher, encrypted_password):
   return cipher.decrypt(encrypted_password.encode()).decode()

def key_exists():
    return os.path.isfile(os.getenv('ZIP_NAME'))

def recovery_exists():
    return os.path.isfile(os.getenv('RECOVERY_ZIP_NAME'))

def delete_key(file):
        os.remove(file)

def save_key(encryption_key, master_password):
    with pyzipper.AESZipFile(os.getenv('ZIP_NAME'),'w',compression=pyzipper.ZIP_LZMA,encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(master_password.encode('utf-8'))
        zf.writestr(os.getenv('KEY_NAME'), encryption_key)

def save_recovery_key(encryption_key, recovery_key):
    with pyzipper.AESZipFile(os.getenv('RECOVERY_ZIP_NAME'),'w',compression=pyzipper.ZIP_LZMA,encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(recovery_key.encode('utf-8'))
        zf.writestr(os.getenv('KEY_NAME'), encryption_key)

def read_key_from_zip(master_password):
    with pyzipper.AESZipFile(os.getenv('ZIP_NAME')) as zf:
        zf.setpassword(master_password.encode('utf-8'))
        encryption_key = zf.read(os.getenv('KEY_NAME'))
    
    return encryption_key

def read_key_from_recovery_zip(recovery_key):
    with pyzipper.AESZipFile(os.getenv('RECOVERY_ZIP_NAME')) as zf:
        zf.setpassword(recovery_key.encode('utf-8'))
        encryption_key = zf.read(os.getenv('KEY_NAME'))
    
    return encryption_key

def generate_strong_password(length=16):
    all_characters = string.ascii_letters + string.digits + '!#$%&()*+-.<=>?@^_'
    password = [
        random.choice(string.ascii_lowercase),  
        random.choice(string.ascii_uppercase),  
        random.choice(string.digits),           
        random.choice('!#$%&()*+-.<=>?@^_')       
    ]
    password += random.choices(all_characters, k=length - 4)
    random.shuffle(password)    
    return ''.join(password)

