import os,click
from dotenv import load_dotenv
import pyperclip
from key import *
from vault import *
from auth import login, validate_master_password, hash_password
from colorama import Fore, Style
from db_functions import *
import getpass

load_dotenv()

@click.group
def app_commands():
    pass

@click.command()
@click.option('-mp','--master-password', prompt='Enter a strong master password', help='The master password to create a new vault')
def register(master_password):
    """Create a new vault by registering a master password"""
    if not vault_already_exists():
        errors = validate_master_password(master_password)
        if errors != "":
            print(Fore.RED,errors)
            print(Style.RESET_ALL)
        create_vault()
        create_tables()
        recovery_key = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for i in range(32))
        salt_master,hashed_master_password = hash_password(master_password)
        salt_recovery,hashed_recovery_key = hash_password(recovery_key)
        create_user(salt_master,hashed_master_password,hashed_recovery_key,salt_recovery)
        encryption_key = generate_key()
        if not key_exists():
            save_key(encryption_key, master_password)
        print(Fore.GREEN,"Encryption key generated, keep it in a safe place", recovery_key)
        print(Fore.YELLOW,"Your recovery key is: ", recovery_key)
        print("The recovery key is the ONLY way to get your vault back in case you forget the master password, keep it safe")
        print(Style.RESET_ALL)
    else:
        print(Fore.RED,"Vault already exists, please use the login option to access your vault")

@click.command
@click.option('-p','--password', prompt="Insert the password to save")
@click.option('-e','--email', prompt="Insert the email to save")
@click.option('-n','--name', prompt="Insert the name to save", default="")
def add(password, email, name):
    if not key_exists():
        print(f"{Fore.RED}Error: Encryption key does not exist{Fore.RESET}")
        return
    if not vault_already_exists():
            print(f"{Fore.RED}Error: Vault does not exist{Fore.RESET}")
            return
    master_password = getpass.getpass("Insert the master password: ")
    if master_password and login(master_password):
        key = read_key_from_zip(master_password)
        cipher = initialize_cipher(key)
        encrypted_password = encrypt_password(cipher, password)
        add_password(encrypted_password, email, name)
        print(f"{Fore.GREEN}Password saved successfully{Fore.RESET}")
    else:
         print(f"{Fore.RED}Error: A valid master password is required{Fore.RESET}")

@click.command
def list():
    if not key_exists():
        print(f"{Fore.RED}Error: Encryption key does not exist{Fore.RESET}")
        return
    if not vault_already_exists():
            print(f"{Fore.RED}Error: Vault does not exist{Fore.RESET}")
            return
    passwords = list_passwords()
    if passwords:
        print("{:<15}{:<30}{:<37}{:>}".format("Id","Name","Email","Password"))
        print("-"*182)
        for password in passwords:
            print("{:<15}{:<30}{:<37}{:>}".format(password[0],password[3],password[2],password[1]))
    else:
         print(f"{Fore.RED}Error: No passwords found{Fore.RESET}")

@click.command
@click.option('-i','--id', prompt="Insert the id of the password you want to decrypt")
@click.option('-c','--copy', is_flag=True)
def decrypt(id,copy):
    if not key_exists():
        print(f"{Fore.RED}Error: Encryption key does not exist{Fore.RESET}")
        return
    if not vault_already_exists():
            print(f"{Fore.RED}Error: Vault does not exist{Fore.RESET}")
            return
    master_password = getpass.getpass("Insert the master password: ")
    if master_password:
        encrypted_password = get_password_by_id(id)
        if encrypted_password != None:
            key = read_key_from_zip(master_password)
            cipher = initialize_cipher(key)
            decrypted_password = decrypt_password(cipher, encrypted_password)
            print(f"{Fore.GREEN}Decrypted password: {decrypted_password}\n{Fore.RESET}")
            if copy:
                pyperclip.copy(decrypted_password)
                print(f"{Fore.GREEN}Copied to clipboard!\n{Fore.RESET}")       
        else:
            print(f"{Fore.RED}Error: Password not found{Fore.RESET}")
    else:
         print(f"{Fore.RED}Error: Master password is required{Fore.RESET}")

@click.command
@click.option('-i','--id', prompt="Insert the id of the password you want to delete")
def delete(id):
    if not vault_already_exists():
            print(f"{Fore.RED}Error: Vault does not exist{Fore.RESET}")
            return
    master_password = getpass.getpass("Insert the master password: ")
    if master_password:
        if login(master_password):
            delete_password_by_id(id)
            print(f"{Fore.GREEN}Password deleted successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Error: Incorrect master password{Fore.RESET}")
    else:
        print(f"{Fore.RED}Error: Master password is required{Fore.RESET}")


@click.command
@click.option('-op','--old-password', prompt="Insert the old password")
@click.option('-np','--new-password', prompt="Insert the new password")
def change(old_password,new_password):
    errors = validate_master_password(new_password)
    if errors:
        print(f"{Fore.RED}Error: {errors}\n{Fore.RESET}")
        return
    
    if login(old_password):
        if vault_already_exists():
            passwords = list_passwords()
            if passwords:
                print(old_password," | ",new_password)
                key = read_key_from_zip(old_password)
                cipher = initialize_cipher(key)
                for password in passwords:
                    old_encrypted_password = password[1]
                    old_decrypted_password = decrypt_password(cipher, old_encrypted_password)
                    new_encrypted_password = encrypt_password(cipher, old_decrypted_password)
                    update_saved_password(password[0], new_encrypted_password)
            delete_key()
            save_key(key,new_password)
            new_salt,new_hash = hash_password(new_password)
            update_master_password(new_hash,new_salt)
            print(f"{Fore.GREEN}Master password changed successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Error: Vault does not exist{Fore.RESET}")
    else:
        print(f"{Fore.RED}Error: The old password is incorrect{Fore.RESET}")
    

    



app_commands.add_command(register)
app_commands.add_command(add)
app_commands.add_command(list)
app_commands.add_command(decrypt)
app_commands.add_command(delete)
app_commands.add_command(change)

if __name__ == "__main__":
    app_commands()