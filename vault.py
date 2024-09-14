import os
from dotenv import load_dotenv
import sqlite3

load_dotenv()

def create_vault():
    conn = sqlite3.connect(os.getenv('VAULT_NAME'))
    print(f"Database '{os.getenv('VAULT_NAME')}' created successfully.")
    conn.close()


def vault_already_exists():
    return os.path.isfile(os.getenv('VAULT_NAME'))


