# Offile password manager

This is a simple terminal based offline password manager that stores your passwords in a local sqlite3 vault, the passwords are encrypted using a **256 bit** symmetric key with **AES** algorithm in **CBC** mode. The encryption key is stored in an encrypted zip file protected by the **master password** chosen during the vault generation, this helps prevent any password leaks in the event of a unauthorized access to the database. Upon registration the user is given a unique **recovery** key that must be safely stored as it is the only way of recovering the vault in case he forgets the master password.

## How to install
Download the files and type the following commands:
```
pip install -r requirements.txt
python main.py register
```


## Structure of database
The database is structured as follows:
#### User table
- *Password*
- *Salt_password*
- *Recovery_key*
- *Salt_recovery*

#### Password table
- *Id*
- *Name*
- *Email*
- *Encrypted_password*

## Commands
- **register**: Generates a new vault with a master password, this will create a new encrypted zip
- **add**: Adds a new password to the vault
- **list**: Lists all the passwords in the vault
- **delete**: Deletes a password from the vault
- **decrypt**: Decrypts a password from the vault
- **change**: Changes the master password of the encryption key
- **recover**: Recover your vault if you forget your master password


