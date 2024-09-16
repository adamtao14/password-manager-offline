import re, hashlib
from dotenv import load_dotenv
from vault import *
from db_functions import get_user_password_and_salt, get_user_recovery_and_salt

from key import *

load_dotenv()

def hash_password(password):
    salt = os.urandom(16)
    sha256 = hashlib.sha256()
    sha256.update(salt + password.encode())
    return salt.hex(), sha256.hexdigest()

def check_hash(stored_salt, stored_hash, password_to_check):
    salt = bytes.fromhex(stored_salt)
    sha256 = hashlib.sha256()
    sha256.update(salt + password_to_check.encode())
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

        if not re.search(r'[!#$%&()*+-.<=>?@^_]', master_password):
            error_messages += "Master password must contain at least one special character.[!#$%&()*+-.<=>?@[]^_]\n"

        if re.search(r'\s', master_password):
            error_messages += "Master password cannot contain spaces.\n"

        return error_messages


def validate(stored_data_func, input_value):
    user_data = stored_data_func()
    if user_data:
        stored_hash, stored_salt = user_data
        if check_hash(stored_salt, stored_hash, input_value):
            return True
    return False

def login(master_password):
    return validate(get_user_password_and_salt, master_password)

def recovery(recovery_key):
    return validate(get_user_recovery_and_salt, recovery_key)


    

    
