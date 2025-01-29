from tkinter import Tk, Label, Entry, Text, Button, Frame, messagebox, END
from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac, sha512
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hmac


def encrypt(message, password):
    salt = get_random_bytes(20)
    key = pbkdf2_hmac('sha1', password.encode(), salt, 65556, dklen=32)
    aes_key, hmac_key = key[:16], key[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    padding_length = AES.block_size - len(message.encode()) % AES.block_size
    padded_message = message + chr(padding_length) * padding_length
    encrypted_message = cipher.encrypt(padded_message.encode())
    data_to_authenticate = salt + iv + encrypted_message
    hmac_code = hmac.new(hmac_key, data_to_authenticate, sha512).digest()
    encrypted_data = salt + iv + encrypted_message + hmac_code
    return b64encode(encrypted_data).decode()


def decrypt(encrypted_message, password):
    encrypted_data = b64decode(encrypted_message)
    salt = encrypted_data[:20]
    iv = encrypted_data[20:20 + AES.block_size]
    hmac_code = encrypted_data[-64:]
    encrypted_message = encrypted_data[20 + AES.block_size:-64]
    key = pbkdf2_hmac('sha1', password.encode(), salt, 65556, dklen=32)
    aes_key, hmac_key = key[:16], key[16:]
    data_to_authenticate = salt + iv + encrypted_message
    expected_hmac = hmac.new(hmac_key, data_to_authenticate, sha512).digest()
    if not hmac.compare_digest(hmac_code, expected_hmac):
        raise ValueError("Message integrity check failed!")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(encrypted_message).decode()
    padding_length = ord(padded_message[-1])
    return padded_message[:-padding_length]

# GUI Functions
def handle_encrypt():
    message = input_message.get("1.0", END).strip()
    password = password_entry.get().strip()
    if not message or not password:
        messagebox.showerror("Error", "Message or Password cannot be empty!")
        return
    try:
        encrypted_text = encrypt(message, password)
        output_message.delete("1.0", END)
        output_message.insert("1.0", encrypted_text)
        output_label.config(text="Message Encrypted Successfully!", fg="green")
    except Exception as e:
        messagebox.showerror("Encryption Error", f"An error occurred: {e}")

def handle_decrypt():
    encrypted_message = input_message.get("1.0", END).strip()
    password = password_entry.get().strip()
    if not encrypted_message or not password:
        messagebox.showerror("Error", "Encrypted Message or Password cannot be empty!")
        return
    try:
        decrypted_text = decrypt(encrypted_message, password)
        output_message.delete("1.0", END)
        output_message.insert("1.0", decrypted_text)
        output_label.config(text="Message Decrypted Successfully!", fg="green")
    except Exception as e:
        messagebox.showerror("Decryption Error", f"An error occurred: {e}")

# UI
root = Tk()
root.title("AES + HMAC Secure Messaging")
root.geometry("700x550")
root.resizable(False, False)
root.configure(bg="#f3f4f6")

# Frame for Inputs
input_frame = Frame(root, bg="#f3f4f6")
input_frame.pack(anchor="center", pady=20)

Label(input_frame, text="Enter Message:", bg="#f3f4f6", font=("Arial", 12)).grid(row=0, column=0, columnspan=2, pady=5)
input_message = Text(input_frame, height=8, width=68, wrap="word", font=("Arial", 10))
input_message.grid(row=1, column=0, columnspan=2, pady=5)

Label(input_frame, text="Enter Password:", bg="#f3f4f6", font=("Arial", 12)).grid(row=2, column=0, columnspan=2, pady=5)
password_entry = Entry(input_frame, show="*", width=53, font=("Arial", 12))
password_entry.grid(row=3, column=0, columnspan=2, pady=5)

# Action Buttons
button_frame = Frame(root, bg="#f3f4f6")
button_frame.pack(anchor="center", pady=10)

Button(button_frame, text="Encrypt", command=handle_encrypt, bg="#4CAF50", fg="white", font=("Arial", 12),
       width=15).grid(row=0, column=0, padx=20, pady=5)
Button(button_frame, text="Decrypt", command=handle_decrypt, bg="#2196F3", fg="white", font=("Arial", 12),
       width=15).grid(row=0, column=1, padx=20, pady=5)

# Output Section
output_frame = Frame(root, bg="#f3f4f6")
output_frame.pack(anchor="center", pady=20)

Label(output_frame, text="Output:", bg="#f3f4f6", font=("Arial", 12)).grid(row=0, column=0, pady=5)
output_message = Text(output_frame, height=8, width=68, wrap="word", state="normal", bg="#f9f9f9", font=("Arial", 10))
output_message.grid(row=1, column=0, pady=5)

output_label = Label(output_frame, text="", bg="#f3f4f6", font=("Arial", 10), fg="red")
output_label.grid(row=2, column=0, pady=5)

# Run the Application
root.mainloop()
