from cryptography.fernet import Fernet
# key is equal to a random symmetric encryption key which is a base64-encoded 32-byte string
key = Fernet.generate_key()
with open("secret.key", "wb") as key_file:
    #this is written meaning a new key is used every single time the file is ran
    key_file.write(key)

print("Encryption key saved to secret.key")