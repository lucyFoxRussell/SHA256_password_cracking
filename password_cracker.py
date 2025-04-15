from pwn import *
import sys
import hashlib

def sha256_hash(text):
    """
    Returns the SHA-256 hash of the given text (string).
    """
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def compare_againsts_most_popular_passwords_hashed(target_hash, password_file): 
    with open(password_file, "r", encoding='utf-8') as password_list:
        for attempt, password in enumerate(password_list):
            if attempt == 10:
                break
            print(f"[{attempt}] Attempting to crack: {target_hash}! \n")
            password = password.strip("\n")
            password_hash = sha256_hash(password)

            if password_hash == target_hash:
                return password
    return None
        

if __name__ == "__main__":
    # Test Example
    target_hash = hashlib.sha256("test".encode('utf-8')).hexdigest()
    password_file = "1K-most-used-passwords-NCSC.txt"

    result = compare_againsts_most_popular_passwords_hashed(target_hash, password_file)
    if result is not None:
        print(f"[+] Password found: '{result}'")
    else:
        print("[!] No match found in the wordlist.")