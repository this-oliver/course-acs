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
""" Step 1: create private and public keys

1. create private key and public key => pr1 & pu1
2. create hash on pu1 => h1
3. encrypts the hash with their private key to create a cipher text => c1
4. send the pu1 and c1 to P2

"""

rsa_key_length = 512
rsa_exponent = 65537
print("\n======> Creating private and public keys with the key length", rsa_key_length, " and the public exponent ", rsa_exponent)

# Generate a private key.
private_key = acs_tool.generate_private_key(rsa_exponent, rsa_key_length)
# Extract the public key from the private key.
public_key = private_key.public_key()
# Convert keys into bytes
private_key_bytes = acs_tool.prk_to_bytes(private_key)
public_key_bytes = acs_tool.puk_to_bytes(public_key)
print("\n======> (P1 private key)\n\n", private_key_bytes)
print("\n======> (P1 public key)\n\n", public_key_bytes)

# Prepare package
hash_public_key_bytes = acs_tool.hash_message(public_key_bytes)
hash_public_key_int = acs_tool.bytes_to_int(hash_public_key_bytes)
print("\n======> Hash of public key created")

cipher_text_mpz = acs_tool.rsa_encrypt(hash_public_key_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
print("\n======> Cipher of hash created")

package = ([public_key_bytes, cipher_text_mpz])
data = pickle.dumps(package)
UDPClientSocket.sendto(data, serverAddressPort)
print("\nsent package. waiting for reply...")

online = True
new_connection = True
line_is_secure = False
authentic_public_key = False

symmetric_key_bytes = None
symmetric_key_iv_bytes = None

newPackage = UDPClientSocket.recvfrom(bufferSize)
print("\npackage received")

# Wait for P2's response
while(online):

    if(new_connection == True):
        data = pickle.loads(newPackage[0])

        p2_public_key_bytes = data[0]
        p2_cipher_public_key_hash_int = data[1]

        cipher_symmetric_key_int = data[2]
        cipher_symmetric_key_iv_int = data[3]

        """ Step 3.1 Verify P2's public key
        1. [P1] decrypts c3 with their pr1 => pt2 (sk1 + h3)
        2. [p1] create a hash of pu2 => h4
        3. [P1] verifies h3 is equal to h4 
        """

        p2_public_key = acs_tool.puk_bytes_to_puk(p2_public_key_bytes)
        p2_public_key_hash_bytes = acs_tool.hash_message(p2_public_key_bytes)

        plain_text_int = acs_tool.rsa_decrypt(p2_cipher_public_key_hash_int, p2_public_key.public_numbers().e, p2_public_key.public_numbers().n)
        plain_text_bytes = acs_tool.int_to_bytes(plain_text_int)

        authentic_public_key = True if p2_public_key_hash_bytes == plain_text_bytes else False
        print("\n======> P2 public key verified: {}".format(authentic_public_key))

        # Enter code block if P2 public key has been verified
        if(authentic_public_key == True):
            new_connection = False
            line_is_secure = True
            print("\n======> Line Secure: {}".format(line_is_secure))
            print("\n======> Authentic P2 Key: {}".format(authentic_public_key))

            """ Step 3.2 Extract symetric key
            1. [P1] encrypts message with sk1 => c4
            2. [P1] sends message to P2
            3. [P2] decrypts message with sk1 => pt3
            """

            symmetric_key_as_int = acs_tool.rsa_decrypt(cipher_symmetric_key_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
            symmetric_key_bytes = acs_tool.int_to_bytes(symmetric_key_as_int)
            print("\n======> Symetric key extracted")

            symmetric_key_iv_as_int = acs_tool.rsa_decrypt(cipher_symmetric_key_iv_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
            symmetric_key_iv_bytes = acs_tool.int_to_bytes(symmetric_key_iv_as_int)
            print("\n======> Symetric key iv extracted")

            print("\n===================(Message Received)===================")
            secret_message_bytes = input("\n ---- Enter Secret Message: ").encode()

            cipher = acs_tool.aes_encrypt(secret_message_bytes, symmetric_key_bytes, symmetric_key_iv_bytes)
            print("\n======> Secret message encrypted")

            package = ([cipher])
            message = pickle.dumps(package)

            UDPClientSocket.sendto(message, serverAddressPort)
            print("\n###################################################################")
            print("package sent: \n{}".format(message))
            print("\n###################################################################")
            print("\nwaiting for reply...")

        else:
            online = False
            print("\n###################################################################")
            print("Not Secure: Public key does not match attached hash\n")
            print("P2 plain text: \n{}".format(plain_text_bytes))
            print("P2 public key hash: \n{}".format(p2_public_key_hash_bytes))
            print("\n###################################################################")

    # only after establishing a secure line
    elif(line_is_secure == True and authentic_public_key == True):
        newPackage = UDPClientSocket.recvfrom(bufferSize)
        data = pickle.loads(newPackage[0])

        # extract iv and cipher text
        p2_cipher_bytes = data[0]

        # decrypt cipher
        plain_text_bytes = acs_tool.aes_decrypt( p2_cipher_bytes, symmetric_key_bytes, symmetric_key_iv_bytes)
        print("\n===================(Message Received)===================")
        print("\n ---- P2 says: {}".format(plain_text_bytes))

        secret_message_bytes = input("\n ---- Enter secret reply: ").encode()
        cipher = acs_tool.aes_encrypt( secret_message_bytes, symmetric_key_bytes, symmetric_key_iv_bytes)

        package = ([cipher])
        message = pickle.dumps(package)

        UDPClientSocket.sendto(message, serverAddressPort)
        print("\n###################################################################")
        print("package sent: \n{}".format(message))
        print("\n###################################################################")
        print("\nwaiting for reply...")

    # something went wrong
    else:
        online = False
        print("\n###################################################################")
        print("Line is no longer secure")
        print("\n###################################################################")
