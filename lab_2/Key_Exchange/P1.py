#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 13 12:47:58 2021

@author: christer
"""

import socket
import pickle
import acs_tool

# Create a UDP socket
serverAddressPort = ("127.0.0.1", 3010)
bufferSize = 1024
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Contact P2
""" Step 1
1. create private key and public key => pr1 & pu1
2. create hash on pu1 => h1
3. encrypts the hash with their private key to create a cipher text => c1
4. send the pu1 and c1 to P2
"""

rsa_key_length = 512
rsa_exponent = 65537

print("\n === P1 key length ===\n", rsa_key_length)
print("\n === P1 public exponent ===\n", rsa_exponent)

# Generate a private key.
private_key = acs_tool.generate_private_key(rsa_exponent, rsa_key_length)
private_key_exponent = private_key.private_numbers().d
private_key_number = private_key.private_numbers().public_numbers.n

# Extract the public key from the private key.
public_key = private_key.public_key()
public_key_exponent = public_key.public_numbers().e
public_key_number = public_key.public_numbers().n


# Convert keys into bytes
private_key_bytes = acs_tool.prk_to_bytes(private_key)
public_key_bytes = acs_tool.puk_to_bytes(public_key)

print("\n === P1 private key ===\n\n", private_key_bytes)
print("\n === P1 public key ===\n\n", public_key_bytes)

## Prepare package

hash_public_key = acs_tool.hash_message(public_key_bytes)
hash_as_int = acs_tool.bytes_to_int(hash_public_key.digest())

print("\n === P1 public key hash ===\n\n", hash_as_int)

cipher_text = acs_tool.rsa_encrypt(hash_as_int, private_key_exponent, private_key_number)
print("\n === P1 hash cipher ===\n\n", cipher_text)

package = ([public_key_bytes, cipher_text])
data = pickle.dumps(package)

msg = "\nMessage to be sent to P2: \n{}".format(data)
print(msg)

UDPClientSocket.sendto(data, serverAddressPort)

online = True
symmetric_key = None
symmetric_key_iv = None
new_connection = True
line_is_secure = False
authentic_public_key = False

newPackage = UDPClientSocket.recvfrom(bufferSize)

while(online):
  # P2's initial response
  if(new_connection == True):
    data = pickle.loads(newPackage[0])
    p2_public_key_bytes = data[0]
    p2_cipher_text_of_hash = data[1]
    pk = "\nP1 key: \n{}".format(p2_public_key_bytes)
    ct = "\nP1 cipher: \n{}".format(p2_cipher_text_of_hash)
    print(pk)
    print(ct)

    p2_public_key = acs_tool.puk_bytes_to_puk(p2_public_key_bytes)
    p2_public_key_exponent = p2_public_key.public_numbers().e
    p2_public_key_number = p2_public_key.public_numbers().n

    plaint_text_as_int = acs_tool.rsa_decrypt(p2_cipher_text_of_hash, p2_public_key_exponent, p2_public_key_number)
    pt = "\nP1 plain text: \n{}".format(plaint_text_as_int)
    print(pt)

    p2_public_key_hash = acs_tool.hash_message(p2_public_key_bytes)
    p2_public_key_hash_as_int = acs_tool.bytes_to_int(p2_public_key_hash.digest())
    hash = "\nP1 pu1 hash: \n{}".format(p2_public_key_hash_as_int)
    print(hash)

    p2_public_key_hash = acs_tool.int_to_bytes(p2_public_key_hash_as_int)
    plain_text = acs_tool.int_to_bytes(plaint_text_as_int)

    authentic_public_key = True if p2_public_key_hash == plain_text else False
    print("\nIs P2 public key valid: {}".format(authentic_public_key))

    if(authentic_public_key == True):
      new_connection = False
      line_is_secure = True

      p2_cipher_text_of_symmetric_key = data[2]
      symmetric_key_as_int = acs_tool.rsa_decrypt(p2_cipher_text_of_symmetric_key, private_key_exponent, private_key_number)
      symmetric_key = acs_tool.int_to_bytes(symmetric_key_as_int)
      print("\nline secure: {}".format(line_is_secure))
      print("\nauthentic p2 key: {}".format(authentic_public_key))

      user_input = input("\nEnter Secret Message: ").encode()

      iv = acs_tool.aes_get_iv()
      #cipher = acs_tool.aes_encrypt(user_input, symmetric_key, iv)
      cipher = acs_tool.aes_encrypt(user_input, b'v9y$B&E)H@McQfTj', iv)

      package = ([cipher, iv])
      message = pickle.dumps(package)

      UDPClientSocket.sendto(message, serverAddressPort)
      print("\n === P1 message sent ===\n\n", message)

  # only after establishing a secure line
  elif(line_is_secure == True and authentic_public_key == True):
    newPackage = UDPClientSocket.recvfrom(bufferSize)  
    data = pickle.loads(newPackage[0])

    # extract iv and cipher text
    p2_cipher = data[0]
    p2_iv = data[1]

    # decrypt cipher
    plain_text = acs_tool.aes_decrypt(p2_cipher, b'v9y$B&E)H@McQfTj', p2_iv)
    secret = plain_text
    print("\nP2 says: \n{}".format(secret))

    user_input = input("\nEnter Secret Message: ").encode()

    iv = acs_tool.aes_get_iv()
    #cipher = acs_tool.aes_encrypt(user_input, symmetric_key, iv)
    cipher = acs_tool.aes_encrypt(user_input, b'v9y$B&E)H@McQfTj', iv)

    package = ([cipher, iv])
    message = pickle.dumps(package)

    UDPClientSocket.sendto(message, serverAddressPort)
    print("\n === P1 message sent ===\n\n", message)
  
  # something went wrong
  else:
    online = False
    print("\nLine is no longer secure\n")
  
  print("\nwaiting...\n")

  #This is a comment
