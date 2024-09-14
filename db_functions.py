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
    # print success
    
    print("Tables created successfully")

def create_user(salt_master,hashed_master_password, hashed_recovery_key,salt_recovery):
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    new_user = (hashed_master_password,hashed_recovery_key,salt_master,salt_recovery)
    cursor_obj.execute("INSERT INTO USER (Password, Recovery_key, Salt_master, Salt_recovery) VALUES (?, ?, ?, ?)", new_user)
    connection.commit()
    connection.close()

def get_user_password_and_salt():
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    cursor_obj.execute("SELECT Password, Salt_master FROM USER LIMIT 1")
    user_data = cursor_obj.fetchone()
    connection.close()
    return user_data

def add_password(encrypted_password, email, name):
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    new_password = (encrypted_password, email, name)
    cursor_obj.execute("INSERT INTO PASSWORD (Encrypted_password, Email, Name) VALUES (?, ?, ?)", new_password)
    connection.commit()
    connection.close()

def list_passwords():
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    cursor_obj.execute("SELECT * FROM PASSWORD")
    passwords = cursor_obj.fetchall()
    connection.close()
    return passwords

def get_password_by_id(id):
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    cursor_obj.execute("SELECT * FROM PASSWORD WHERE Id = ?", (id,))
    password = cursor_obj.fetchone()
    connection.close()
    if password:
        return password[1]
    else:
        return None

def delete_password_by_id(id):
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    cursor_obj.execute("DELETE FROM PASSWORD WHERE Id = ?", (id,))
    connection.commit()
    connection.close()
    
def update_saved_password(id, new_encrypted_password):
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    cursor_obj.execute("UPDATE PASSWORD SET Encrypted_password = ? WHERE Id = ?", (new_encrypted_password,id))
    connection.commit()
    connection.close()

def update_master_password(new_hashed_password, new_salt):
    connection = sqlite3.connect(os.getenv('VAULT_NAME'))
    cursor_obj = connection.cursor()
    cursor_obj.execute("UPDATE USER SET Password = ?, Salt_master = ? WHERE rowid = 1",(new_hashed_password,new_salt))
    connection.commit()
    connection.close()