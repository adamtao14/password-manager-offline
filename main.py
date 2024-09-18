import os,click,getpass,pyperclip
from dotenv import load_dotenv
from key import *
from vault import *
from auth import login, validate_master_password, hash_password,recovery
from colorama import Fore, Style
from db_functions import *


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
            return
        create_vault()
        create_tables()
        recovery_key = generate_recovery_key()
        salt_master,hashed_master_password = hash_password(master_password)
        salt_recovery,hashed_recovery_key = hash_password(recovery_key)
        create_user(salt_master,hashed_master_password,hashed_recovery_key,salt_recovery)
        encryption_key = generate_key()
        if not key_exists() and not recovery_exists():
            save_key(encryption_key, master_password)
            save_recovery_key(encryption_key, recovery_key)
        print(Fore.GREEN,"Encryption key generated in",os.getenv('ZIP_NAME'))
        print(Fore.YELLOW,"Your recovery key is: ", recovery_key)
        print("The recovery key is the ONLY way to get your vault back in case you forget the master password, keep it safe")
        print(Style.RESET_ALL)
    else:
        print(Fore.RED,"Vault already exists, please use the login option to access your vault")

@click.command
@click.option('-p','--password')
@click.option('-e','--email', prompt="Insert the email to save")
@click.option('-n','--name', prompt="Insert the name to save", default="")
def add(password, email, name):
    if not key_exists():
        print(f"{Fore.RED}Error: Encryption key does not exist{Fore.RESET}")
        return
    if not vault_already_exists():
            print(f"{Fore.RED}Error: Vault does not exist{Fore.RESET}")
            return
    master_password = getpass.getpass("Insert the master password:")
    if master_password and login(master_password):
        key = read_key_from_zip(master_password)
        cipher = initialize_cipher(key)
        if not password:
            password = generate_strong_password()
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
    master_password = getpass.getpass("Insert the master password:")
    if master_password and login(master_password):
        passwords = list_passwords()
        if passwords:
            print("{:<15}{:<30}{:<37}{:>}".format("Id","Name","Email","Password"))
            print("-"*182)
            for password in passwords:
                print("{:<15}{:<30}{:<37}{:>}".format(password[0],password[3],password[2],password[1]))
        else:
            print(f"{Fore.RED}Error: No passwords found{Fore.RESET}")
    else:
        print(f"{Fore.RED}Error: A valid master password is required{Fore.RESET}")

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
        if vault_already_exists() and key_exists():
            key = read_key_from_zip(old_password)
            delete_key(os.getenv('ZIP_NAME'))
            save_key(key,new_password)
            new_salt,new_hash = hash_password(new_password)
            update_master_password(new_hash,new_salt)
            print(f"{Fore.GREEN}Master password changed successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Error: Vault or key does not exist{Fore.RESET}")
    else:
        print(f"{Fore.RED}Error: The old password is incorrect{Fore.RESET}")
    
@click.command
@click.option('-rk','--recovery-key', prompt="Insert the recovery key")
@click.option('-np','--new-password', prompt="Insert the new password")
def recover(recovery_key, new_password):
    if vault_already_exists() and recovery_exists() and key_exists():
        if recovery(recovery_key):
            errors = validate_master_password(new_password)
            if errors:
                print(f"{Fore.RED}Error: {errors}\n{Fore.RESET}")
                return
            else:
                new_salt_master,new_hash_master = hash_password(new_password)
                new_recovery_key = generate_recovery_key()
                new_salt_recovery,new_hash_recovery = hash_password(new_recovery_key)
                update_master_password(new_hash_master,new_salt_master)
                update_recovery_key(new_hash_recovery,new_salt_recovery)
                
                encryption_key = read_key_from_recovery_zip(recovery_key)
                if encryption_key:
                    delete_key(os.getenv('ZIP_NAME'))
                    delete_key(os.getenv('RECOVERY_ZIP_NAME'))
                    save_key(encryption_key,new_password)
                    save_recovery_key(encryption_key,new_password)
                    print(f"{Fore.GREEN}Master password changed successfully{Fore.RESET}")
                else:
                    print(f"{Fore.RED}Error: Problem reading the recovery key{Fore.RESET}")
        else:
            print(f"{Fore.RED}Error: The recovery key is incorrect{Fore.RESET}")
    else:
        print(f"{Fore.RED}Error: Vault or key does not exist{Fore.RESET}")

@click.command
@click.option('-l','--length', default="16")
@click.option('-c','--copy', is_flag=True)
def generate(length=16,copy=False):
    if int(length) < 16:
        print(f"{Fore.RED}Error: The password length must be at least 16 characters{Fore.RESET}")
        return
    else:
        password = generate_strong_password(int(length))
        print(f"{Fore.GREEN}Generated password: {password}{Fore.RESET}")
        if copy:
                pyperclip.copy(password)
                print(f"{Fore.GREEN}Copied to clipboard!\n{Fore.RESET}")    





app_commands.add_command(register)
app_commands.add_command(add)
app_commands.add_command(list)
app_commands.add_command(decrypt)
app_commands.add_command(delete)
app_commands.add_command(change)
app_commands.add_command(recover)
app_commands.add_command(generate)

if __name__ == "__main__":
    app_commands()