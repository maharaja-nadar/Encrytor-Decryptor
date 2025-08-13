from cryptography.fernet import Fernet

# Generate a valid key
key = Fernet.generate_key()

# Save it to a file
with open("secret.key", "wb") as key_file:
    key_file.write(key)

print("New valid Fernet key generated and saved to secret.key")

