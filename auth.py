import re, hashlib, secrets, string, click
from dotenv import load_dotenv
from vault import *
from db_functions import get_user_password_and_salt

from key import *

load_dotenv()

def hash_password(password):
    salt = os.urandom(16)
    sha256 = hashlib.sha256()
    sha256.update(salt + password.encode())
    return salt.hex(), sha256.hexdigest()

def check_master_password(stored_salt, stored_hash, password_to_check):
    # Convert the stored salt back from hex
    salt = bytes.fromhex(stored_salt)
    
    # Hash the provided password using the stored salt
    sha256 = hashlib.sha256()
    sha256.update(salt + password_to_check.encode())
    
    # Compare the hash of the provided password with the stored hash
    return sha256.hexdigest() == stored_hash


def validate_master_password(master_password):
        error_messages = ""
        
        if not master_password:
            error_messages += 'Master password cannot be empty\n'
        
        if len(master_password) < 12:
            error_messages += "Master password must be at least 12 characters long.\n"

        if not re.search(r'[A-Z]', master_password):
            error_messages += "Master password must contain at least one uppercase letter.\n"

        if not re.search(r'[a-z]', master_password):
            error_messages += "Master password must contain at least one lowercase letter.\n"

        if not re.search(r'[0-9]', master_password):
            error_messages += "Master password must contain at least one digit.\n"

        if not re.search(r'[@#$%^&+=!]', master_password):
            error_messages += "Master password must contain at least one special character.[@#$%^&+=!]\n"

        if re.search(r'\s', master_password):
            error_messages += "Master password cannot contain spaces.\n"

        return error_messages


def login(master_password):
    user_data = get_user_password_and_salt()
    if user_data:
        stored_hash, stored_salt = user_data
        if check_master_password(stored_salt, stored_hash, master_password):
            return True
        else:
            return False
    else:
        return False


    

    
