"""
Created on 16 Sep 2021 14:51:00

@author: olivermanzi
"""

import os
import gmpy2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

################## RSA LOGIC ##################
def int_to_bytes(i):
  """ converts integers into bytes 
  
  => Returns [bytes]
  """
  i = int(i)
  return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
  """ converts bytes into integers 
  
  => Returns [int]
  """
  return int.from_bytes(b, byteorder='big')

def rsa_encrypt(message, exponent, number):
  """ encrypts message with rsa algorithm
  
  [int] message - message

  [int] exponent - encryption key exponent
  
  [int] number - encryption key number

  => Returns [int]
  """
  return gmpy2.powmod(message, exponent, number)

def rsa_decrypt(cipher, exponent, number):
  """ decrypts message with rsa algorithm
  
  [int] message - message

  [int] exponent - encryption key exponent
  
  [int] number - encryption key number

  => Returns [int]
  """
  return gmpy2.powmod(cipher, exponent, number)

def generate_private_key(exponent, key_length):
  """ encrypts message with rsa algorithm
  
  [int] exponent - encryption key exponent
  
  [int] number - encryption key number

  => Returns [Private Key]
  """
  return rsa.generate_private_key(
    public_exponent=exponent,
    key_size=key_length,
    backend=default_backend())

def prk_to_bytes(private_key):
  """ converts private key object into bytes
  
  [private key] private_key

  => Returns [bytes]
  """
  return private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption())

def prk_bytes_to_prk(private_key_bytes):
  """ converts private key bytes into private key object
  
  [private key] private_key

  => Returns [Public Key Type]
  """
  return serialization.load_pem_private_key(
    private_key_bytes,
    backend=default_backend(),
    password=None)

def puk_to_bytes(public_key):
  """ converts public key object into bytes
  
  [public key] public_key

  => Returns [bytes]
  """
  return public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

def puk_bytes_to_puk(public_key_bytes):
  """ converts public key bytes into public key object
  
  [public key] public_key

  => Returns [Public Key Type]
  """
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
  """ encrypts message with aes algorithm
  
  [bytes] message - message

  [bytes] exponent - encryption key exponent
  
  [bytes] number - encryption key number

  => Returns [bytes]
  """
  aesEncryptor = Cipher(algorithms.AES(key),
                   modes.CTR(iv),
                   backend=default_backend()).encryptor()
  return aesEncryptor.update(message)

def aes_decrypt(message, key, iv):
  """ encrypts message with aes algorithm
  
  [bytes] message - message

  [bytes] exponent - encryption key exponent
  
  [bytes] number - encryption key number

  => Returns [bytes]
  """
  aesDecryptor = Cipher(algorithms.AES(key),
                   modes.CTR(iv),
                   backend=default_backend()).decryptor()
  return aesDecryptor.update(message)

################## HASH LOGIC ##################

def hash_message(message):
  return hashlib.sha1(message).digest()