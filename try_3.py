from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt(message, password):
    # Generate random salt
    salt = get_random_bytes(20)

    # Derive key from password and salt using PBKDF2
    key = pbkdf2_hmac('sha1', password.encode(), salt, 65556, dklen=32)

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    # Pad the message to be compatible with AES block size
    padding_length = AES.block_size - len(message.encode()) % AES.block_size
    padded_message = message + chr(padding_length) * padding_length

    # Encrypt the message
    encrypted_message = cipher.encrypt(padded_message.encode())

    # Combine salt, IV, and encrypted message
    encrypted_data = salt + iv + encrypted_message

    # Return Base64-encoded result
    return b64encode(encrypted_data).decode()

def decrypt(encrypted_message, password):
    # Decode Base64-encoded message
    encrypted_data = b64decode(encrypted_message)

    # Extract salt, IV, and encrypted message
    salt = encrypted_data[:20]
    iv = encrypted_data[20:20 + AES.block_size]
    encrypted_message = encrypted_data[20 + AES.block_size:]

    # Derive key from password and salt using PBKDF2
    key = pbkdf2_hmac('sha1', password.encode(), salt, 65556, dklen=32)

    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the message
    padded_message = cipher.decrypt(encrypted_message).decode()

    # Remove padding
    padding_length = ord(padded_message[-1])
    return padded_message[:-padding_length]

if __name__ == "__main__":
    while True:
        # Ask the user for their choice
        print("\nDo you want to Encrypt, Decrypt, or Exit?")
        print("Type 'E' for Encrypt, 'D' for Decrypt, or 'X' to Exit:")
        choice = input().strip().upper()

        if choice == 'X':
            print("Exiting the program.")
            break

        # Ask the user to input the key (password) instead of using a fixed one
        print("Enter your encryption key:")
        password = input().strip()  # Get key input from user
        
        if choice == 'E':
            print("Enter your message to encrypt:")
            message = input()
            encrypted_message = encrypt(message, password)
            print(f"Encrypted Message is: {encrypted_message}")

        elif choice == 'D':
            print("Enter the encrypted message to decrypt:")
            encrypted_message = input()
            try:
                decrypted_message = decrypt(encrypted_message, password)
                print(f"Decrypted Message is: {decrypted_message}")
            except Exception as e:
                print("Decryption failed. Please ensure the input is correct.")

        else:
            print("Invalid choice! Please type 'E' for Encrypt, 'D' for Decrypt, or 'X' to Exit.")
