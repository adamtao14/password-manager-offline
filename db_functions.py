import sqlite3, os, secrets, string
from dotenv import load_dotenv
load_dotenv()

def create_tables():
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()

    cursor_obj.execute("DROP TABLE IF EXISTS USER;")
    cursor_obj.execute("DROP TABLE IF EXISTS PASSWORD;")
    table = """ CREATE TABLE USER (
                Password VARCHAR(255) NOT NULL,
                Recovery_key VARCHAR(255) NOT NULL,
                Salt_master BLOB,
                Salt_recovery BLOB
            ); """
    cursor_obj.execute(table)

    table = """ CREATE TABLE PASSWORD (
                Id INTEGER PRIMARY KEY autoincrement,
                Encrypted_password VARCHAR(255) NOT NULL,
                Email VARCHAR(100) NOT NULL,
                Name VARCHAR(100)
            ); """
    cursor_obj.execute(table)
    connection.commit()
    connection.close()    
    print("Tables created successfully")


def execute_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    cursor_obj.execute(query, params)
    
    result = None
    if fetch_one:
        result = cursor_obj.fetchone()
    elif fetch_all:
        result = cursor_obj.fetchall()
    
    if commit:
        connection.commit()
    
    connection.close()
    return result

# User-related functions
def create_user(salt_master, hashed_master_password, hashed_recovery_key, salt_recovery):
    query = """
    INSERT INTO USER (Password, Recovery_key, Salt_master, Salt_recovery)
    VALUES (?, ?, ?, ?)
    """
    params = (hashed_master_password, hashed_recovery_key, salt_master, salt_recovery)
    execute_query(query, params, commit=True)

def get_user_password_and_salt():
    query = "SELECT Password, Salt_master FROM USER LIMIT 1"
    return execute_query(query, fetch_one=True)

def get_user_recovery_and_salt():
    query = "SELECT Recovery_key, Salt_recovery FROM USER LIMIT 1"
    return execute_query(query, fetch_one=True)

def update_master_password(new_hashed_password, new_salt):
    query = "UPDATE USER SET Password = ?, Salt_master = ? WHERE rowid = 1"
    params = (new_hashed_password, new_salt)
    execute_query(query, params, commit=True)

def update_recovery_key(new_hashed_recovery, new_salt):
    query = "UPDATE USER SET Recovery_key = ?, Salt_recovery = ? WHERE rowid = 1"
    params = (new_hashed_recovery, new_salt)
    execute_query(query, params, commit=True)

def add_password(encrypted_password, email, name):
    query = """
    INSERT INTO PASSWORD (Encrypted_password, Email, Name)
    VALUES (?, ?, ?)
    """
    params = (encrypted_password, email, name)
    execute_query(query, params, commit=True)

def list_passwords():
    query = "SELECT * FROM PASSWORD"
    return execute_query(query, fetch_all=True)

def get_password_by_id(id):
    query = "SELECT Encrypted_password FROM PASSWORD WHERE Id = ?"
    password = execute_query(query, (id,), fetch_one=True)
    return password[0] if password else None

def delete_password_by_id(id):
    query = "DELETE FROM PASSWORD WHERE Id = ?"
    execute_query(query, (id,), commit=True)

def update_saved_password(id, new_encrypted_password):
    query = "UPDATE PASSWORD SET Encrypted_password = ? WHERE Id = ?"
    params = (new_encrypted_password, id)
    execute_query(query, params, commit=True)