#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 13 12:47:58 2021

@author: christer
"""

import socket, json, helper
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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
private_key = helper.generate_private_key(rsa_exponent, rsa_key_length)
private_key_exponent = private_key.private_numbers().d
private_key_number = private_key.private_numbers().public_numbers.n

# Extract the public key from the private key.
public_key = private_key.public_key()
public_key_exponent = public_key.public_numbers().e
public_key_number = public_key.public_numbers().n

# Convert the private key into bytes. We won't encrypt it this time.
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\n === P1 private key ===\n\n", private_key_bytes)
print("\n === P1 public key ===\n\n", public_key_bytes)

# Convert the private key bytes back to a key.
# Because there is no encryption of the key, there is no password.
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    backend=default_backend(),
    password=None)

public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend())

public_key_hash = helper.hash_message(public_key_bytes)
public_key_hash_as_int = helper.bytes_to_int(public_key_hash.digest())
cipher_text = helper.rsa_encrypt(public_key_hash_as_int, private_key_exponent, private_key_number)

print("\n === P1 cipher ===\n\n", cipher_text)

data = json.dumps({"pu": public_key_bytes, "cipher": cipher_text});
msg = "Message to be sent to P2: \n{}".format(data)
print(msg)

UDPClientSocket.sendto(data.encode(), serverAddressPort)

# P1's response
msgFromServer = UDPClientSocket.recvfrom(bufferSize)
msg = "Reply from P2: \n {}".format(msgFromServer[0])
print(msg)