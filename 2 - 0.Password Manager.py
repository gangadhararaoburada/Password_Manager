'''Develop a password manager that securely stores and retrieves passwords.'''

import getpass
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self):
        self._cipher_suite = Fernet(Fernet.generate_key())
        self._passwords = {}

    def store_password(self, service):
        password = getpass.getpass(prompt=f"Enter the password for {service}: ")
        encrypted_password = self._cipher_suite.encrypt(password.encode())
        self._passwords[service] = encrypted_password

    def retrieve_password(self, service):
        encrypted_password = self._passwords.get(service)
        if encrypted_password is not None:
            decrypted_password = self._cipher_suite.decrypt(encrypted_password)
            print(f"The password for {service} is: {decrypted_password.decode()}")
        else:
            print(f"No password stored for {service}.")

def main():
    manager = PasswordManager()
    while True:
        print("\n1: Add password\n2: Retrieve password\n3: Quit")
        user_choice = input("Enter your choice: ")
        if user_choice == '1':
            service = input("Enter the name of the service: ")
            manager.store_password(service)
        elif user_choice == '2':
            service = input("Enter the name of the service: ")
            manager.retrieve_password(service)
        elif user_choice == '3':
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")

if __name__ == "__main__":
    main()
