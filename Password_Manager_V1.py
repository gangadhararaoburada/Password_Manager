'''Develop a password manager that securely stores and retrieves passwords.'''

import sys
import getpass
import logging
import json
import os
from cryptography.fernet import Fernet, InvalidToken

PASSWORDS_FILE = 'passwords.json'
KEY_FILE = 'recover.key'

# Set up logging
logging.basicConfig(
    filename='password_manager.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

def log_and_print(message, level='info'):
    print(message)
    if level == 'info':
        logging.info(message)
    elif level == 'error':
        logging.error(message)
    elif level == 'warning':
        logging.warning(message)

# Print Python version and compatibility status
python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
print(f"Running on Python [ {python_version} ]")
if sys.version_info >= (3, 12):
    log_and_print("     - This version is compatible and supported for the execution of the code.")
else:
    log_and_print("Error: ", 'error')
    log_and_print(f"    - The version [ {python_version} ] is not compatible and not supported for the execution of the code.", 'error')
    log_and_print("    - This code requires Python [ 3.12 ] or later versions.", 'error')
    sys.exit(1)

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
            logging.info("Encryption key loaded from file.")
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        logging.info("Encryption key generated and saved to file.")
    return key

def load_passwords():
    if os.path.exists(PASSWORDS_FILE):
        try:
            with open(PASSWORDS_FILE, 'r') as f:
                data = json.load(f)
            logging.info("Passwords loaded from JSON file.")
            # Convert base64-encoded values back to bytes
            return {k: v.encode() for k, v in data.items()}
        except Exception as e:
            logging.error(f"Error loading passwords: {e}")
            return {}
    return {}

def save_passwords(passwords):
    try:
        # Convert bytes to base64-encoded strings for JSON serialization
        data = {k: v.decode() for k, v in passwords.items()}
        with open(PASSWORDS_FILE, 'w') as f:
            json.dump(data, f)
        logging.info("Passwords saved to JSON file.")
    except Exception as e:
        logging.error(f"Error saving passwords: {e}")

class PasswordManager:
    def __init__(self):
        try:
            key = load_key()
            self._cipher_suite = Fernet(key)
            self._passwords = load_passwords()
            logging.info("PasswordManager initialized successfully.")
        except Exception as e:
            logging.error(f"Failed to initialize PasswordManager: {e}")
            raise

    def store_password(self, service):
        try:
            if not service:
                log_and_print("Service name cannot be empty.", 'warning')
                return
            password = getpass.getpass(prompt=f"Enter the password for {service}: ")
            if not password:
                log_and_print("Password cannot be empty.", 'warning')
                return
            encrypted_password = self._cipher_suite.encrypt(password.encode())
            self._passwords[service] = encrypted_password
            save_passwords(self._passwords)
            logging.info(f"Password stored for service: {service}")
            print(f"Password for '{service}' stored successfully.")
        except Exception as e:
            logging.error(f"Error storing password for {service}: {e}")
            print(f"An error occurred while storing the password for {service}.")

    def display_accounts(self):
        try:
            if self._passwords:
                print("Stored accounts/services:")
                for idx, service in enumerate(self._passwords, 1):
                    print(f"  {idx}. {service}")
                logging.info("Displayed all stored accounts.")
            else:
                print("No accounts/services stored yet.")
                logging.info("No accounts to display.")
        except Exception as e:
            logging.error(f"Error displaying accounts: {e}")
            print("An error occurred while displaying accounts.")

    def retrieve_password(self, service):
        try:
            if not service:
                log_and_print("Service name cannot be empty.", 'warning')
                return
            encrypted_password = self._passwords.get(service)
            if encrypted_password is not None:
                try:
                    decrypted_password = self._cipher_suite.decrypt(encrypted_password)
                    print(f"The password for {service} is: {decrypted_password.decode()}")
                    logging.info(f"Password retrieved for service: {service}")
                except InvalidToken:
                    logging.error(f"Decryption failed for service: {service}")
                    print("Failed to decrypt the password. The data may be corrupted.")
            else:
                log_and_print(f"No password stored for {service}.", 'warning')
        except Exception as e:
            logging.error(f"Error retrieving password for {service}: {e}")
            print(f"An error occurred while retrieving the password for {service}.")

def main():
    try:
        manager = PasswordManager()
        while True:
            print("\n1: Add password\n2: Display accounts\n3: Retrieve password\n4: Quit")
            user_choice = input("Enter your choice: ").strip()
            if user_choice == '1':
                service = input("Enter the name of the service: ").strip()
                manager.store_password(service)
            elif user_choice == '2':
                manager.display_accounts()
            elif user_choice == '3':
                service = input("Enter the name of the service: ").strip()
                manager.retrieve_password(service)
            elif user_choice == '4':
                print("Exiting Password Manager. Goodbye!")
                logging.info("User exited the application.")
                break
            else:
                log_and_print("Invalid choice. Please enter a number between 1 and 4.", 'warning')
    except KeyboardInterrupt:
        log_and_print("\nProcess interrupted by user. Exiting...", 'warning')
    except Exception as e:
        logging.error(f"Unexpected error in main loop: {e}")
        print("An unexpected error occurred. Please check the log file for details.")

if __name__ == "__main__":
    main()
