import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = b'InformationSecurity M.Sc'
message = b"""Applied Securityl"""
iv = os.urandom(16)

aesCipher = Cipher(algorithms.AES(key),
                   modes.CTR(iv),
                   backend=default_backend())

aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

ciphertext = aesEncryptor.update(message)

print("plaintext:",message)
print("ciphertext:",ciphertext.hex())
decryptedMessage = aesDecryptor.update(ciphertext)
print("recovered:",decryptedMessage)