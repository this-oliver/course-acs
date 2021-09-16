import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key = b'InformationSecurity M.Sc'
message = b"""Applied Securityl"""

aesCipher = Cipher(algorithms.AES(key),
                   modes.ECB(),
                   backend=default_backend())

message += b"E" * (-len(message) % 16) # Padding to full blocks of 16 bytes

aesEncryptor = aesCipher.encryptor()
aesDecryptor = aesCipher.decryptor()

ciphertext = aesEncryptor.update(message)

print("plaintext:",message)
print("ciphertext:",ciphertext.hex())
decryptedMessage = aesDecryptor.update(ciphertext)
print("recovered:",decryptedMessage)