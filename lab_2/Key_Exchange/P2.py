#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 13 12:45:02 2021

@author: christer
"""
# P2 acts as a server due to the while loop, listening to a dedicated port.
# In this lab, P2 will both initiate sending messages and respond to messages 
# so you need to implement that. For how to initiate a communication, see P1.py.
# Good luck!  

import socket
import json
import gmpy2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Create a datagram socket and bind to an IP address and port
myIP = "127.0.0.1"
myPort = 3010
bufferSize = 1024
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((myIP, myPort))

# Setup public key logic
def simple_rsa_encrypt(message, exponent, number):
    return gmpy2.powmod(message, exponent, number)

def simple_rsa_decrypt(cipher, exponent, number):
    return gmpy2.powmod(cipher, exponent, number)

def int_to_bytes(i):
    # i might be a gmpy2 big integer; convert back to a Python int
    i = int(i)
    return i.to_bytes((i.bit_length()+7)//8, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def generate_private_key(exponent, key_length):
    return rsa.generate_private_key(
     public_exponent=exponent,
     key_size=key_length,
     backend=default_backend()
     )

# generate public key
key_length = 512
exponent = 65537

# Generate a private key.
private_key = generate_private_key(exponent, key_length);

# Extract the public key from the private key.
public_key = private_key.public_key()

# Convert the private key into bytes. We won't encrypt it this time.
private_key_bytes = private_key.private_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PrivateFormat.TraditionalOpenSSL,
  encryption_algorithm=serialization.NoEncryption())
# Convert the private key bytes back to a key.
# Because there is no encryption of the key, there is no password.
private_key = serialization.load_pem_private_key(
  private_key_bytes,
  backend=default_backend(),
  password=None)

# Convert the public key into bytes.
public_key_bytes = public_key.public_bytes(
  encoding=serialization.Encoding.PEM,
  format=serialization.PublicFormat.SubjectPublicKeyInfo
)
# Convert the private key bytes back to a key.
# Because there is no encryption of the key, there is no password.
public_key = serialization.load_pem_public_key(
  public_key_bytes,
  backend=default_backend())

print("\n === P2 key length ===\n", key_length)
print("\n === P2 public exponent ===\n", exponent)
print("\n === P2 private key ===\n\n", private_key_bytes)
print("\n === P2 public key ===\n\n", public_key_bytes)

print("P2 is up running and ready to go!")
msgFromServer = "Hi P1, Applied Computer Science P2 here, I hope all is secured on your side."
bytesToSend = str.encode(msgFromServer)
# Wait for incomming calls, any one out there? Hopefully P1.
while(True):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    address = bytesAddressPair[1]
    data = bytesAddressPair[0]
    data = json.loads(data.decode())
    msg = "Message from P1: \n{}".format(data)
    sendersIP  = "P1's Address is:{}".format(address)
    
    print(msg)
    print(sendersIP)

    #Send response to P1
    UDPServerSocket.sendto(bytesToSend, address)