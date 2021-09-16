import os
import gmpy2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

################## RSA LOGIC ##################
def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def rsa_encrypt(message, exponent, number):
    return gmpy2.powmod(message, exponent, number)

def rsa_decrypt(cipher, exponent, number):
    return gmpy2.powmod(cipher, exponent, number)

def generate_private_key(exponent, key_length):
    return rsa.generate_private_key(
     public_exponent=exponent,
     key_size=key_length,
     backend=default_backend())

def prk_to_bytes(private_key):
  return private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

def prk_bytes_to_prk(private_key_bytes):
  return serialization.load_pem_private_key(
    private_key_bytes,
    backend=default_backend(),
    password=None)

def puk_to_bytes(public_key):
  return public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

def puk_bytes_to_puk(public_key_bytes):
  return serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend())


################## AES LOGIC ##################
key_128 = b'v9y$B&E)H@McQfTj'
key_256 = b'H@McQfTjWnZr4t7w!z%C*F-JaNdRgUkX'

def aes_get_key_128():
  return key_128

def aes_get_key_256():
  return key_256

def aes_get_iv():
  return os.urandom(16)

def aes_encrypt(message, key, iv):
  aesCipher = Cipher(algorithms.AES(key),
                   modes.CBC(iv),
                   backend=default_backend())
  aesEncryptor = aesCipher.encryptor()
  message += b"E" * (-len(message) % 16) # Padding to full blocks of 16 bytes
  return aesEncryptor.update(message)

def aes_decrypt(message, key, iv):
  aesCipher = Cipher(algorithms.AES(key),
                   modes.CBC(iv),
                   backend=default_backend())
  aesDecryptor = aesCipher.decryptor()
  return aesDecryptor.update(message)

################## HASH LOGIC ##################

def hash_message(message):
  return hashlib.sha1(message)