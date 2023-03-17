import sys
import argparse
import getpass
import sqlite3
import hashlib
import os.path
from typing import List
from Crypto.Cipher import AES
from tabulate import tabulate

DEFAULT_DATABASE = "database.db"


class PasswordManager:
    def __init__(self, master_password: str, database_file: str = DEFAULT_DATABASE):
        self.master_password = master_password
        self.connection = sqlite3.connect(database_file)
        self.cursor = self.connection.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('CREATE TABLE IF NOT EXISTS passwords (website TEXT, username TEXT, password TEXT)')

    def add_password(self, website: str, username: str, password: str):
        encrypted_password = self.encrypt_password(password)
        self.cursor.execute('INSERT INTO passwords VALUES (?, ?, ?)', (website, username, encrypted_password))
        self.connection.commit()
        print(f"Password for {website} has been added successfully")

    def get_password(self, website: str) -> str:
        self.cursor.execute('SELECT password FROM passwords WHERE website = ?', (website,))
        row = self.cursor.fetchone()
        if row:
            encrypted_password = row[0]
            return self.decrypt_password(encrypted_password)
        else:
            return None

    def list_passwords(self) -> List:
        self.cursor.execute('SELECT website, username FROM passwords')
        rows = self.cursor.fetchall()
        return rows

    def encrypt_password(self, password: str) -> bytes:
        key = hashlib.sha256(self.master_password.encode('utf-8')).digest()
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
        return nonce + ciphertext + tag

    def decrypt_password(self, encrypted_password: bytes) -> str:
        key = hashlib.sha256(self.master_password.encode('utf-8')).digest()
        nonce = encrypted_password[:16]
        ciphertext = encrypted_password[16:-16]
        tag = encrypted_password[-16:]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

    def close(self):
        self.connection.close()


def init_password_manager(master_password: str, database_file: str = DEFAULT_DATABASE) -> PasswordManager:
    if not os.path.isfile(database_file):
        open(database_file, 'a').close()
    return PasswordManager(master_password, database_file)


def add_password(password_manager: PasswordManager):
    website = input("Enter website name: ")
    username = input("Enter username: ")
    password = getpass.getpass(prompt="Enter password: ")
    password_manager.add_password(website, username, password)


def get_password(password_manager: PasswordManager):
    website = input("Enter website name: ")
    password = password_manager.get_password(website)
    if password:
        print(f"Password for {website} is: {password}")
    else:
        print(f"No password found for {website}")


def list_passwords(password_manager: PasswordManager):
    rows = password_manager.list_passwords()
    print(tabulate(rows, headers=["Website", "Username"]))


def main(args):
    password_manager = init_password_manager(args.master_password, args.database_file)
    if args.command == "add":
        add_password(password_manager)
    elif args.command == "get":
        get_password(password_manager)
    elif args.command == "list":
        list_passwords(password_manager)
    else:
        print("Invalid command")
        return

    password_manager.close()


