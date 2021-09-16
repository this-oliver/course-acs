import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key1 = b'InformationSecurity M.Sc'
key_128 = b'v9y$B&E)H@McQfTj'
key_256 = b'H@McQfTjWnZr4t7w!z%C*F-JaNdRgUkX'

key = key_128

message = b"""Applied Security"""
iv = os.urandom(16)

aesCipher = Cipher(algorithms.AES(key),
                   modes.CTR(iv),
                   backend=default_backend())

message += b"E" * (-len(message) % 16) # Padding to full blocks of 16 bytes

aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

ciphertext = aesEncryptor.update(message)
decryptedMessage = aesDecryptor.update(ciphertext)

print("#### CTR ####")
print("plaintext:",message)
print("iv:", iv)
print("key:", key)
print("ciphertext:",ciphertext.hex())
print("recovered:",decryptedMessage)