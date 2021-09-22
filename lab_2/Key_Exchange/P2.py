#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 16 Sep 2021 14:51:00

@author: olivermanzi

This code implements a server that 
establishes a connection with a client 
and creates an assymetric key that is 
used to exchange a symmetric key that 
encrypts messages with a client
"""

import socket
import pickle
import helper

# Create a datagram socket and bind to an IP address and port
myIP = "127.0.0.1"
myPort = 3010
bufferSize = 1024
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
UDPServerSocket.bind((myIP, myPort))

print("\nP2 is up running and ready to go!")

online = True
new_connection = True
line_is_secure = False
authentic_public_key = False

symmetric_key_bytes = None
symmetric_key_iv_bytes = None

# Wait for incomming messages from p1
while(online):
    newPackage = UDPServerSocket.recvfrom(bufferSize)
    address = newPackage[1]
    print("\nPackage received!\n")
    print("\nP1's Address is:{}".format(address))

    data = pickle.loads(newPackage[0])

    print("\nLine Secure: {}".format(line_is_secure))
    print("\nAuthentic P1 Key: {}".format(authentic_public_key))

    # If the connection is new, verify the public key
    if(new_connection == True):
        """ Step 2.1 Verify P1's public key
        1. [P2] decrypt cipher text (c1) with P1's pu1 => pt1 (this is essentially h1)
        2. [P2] create a hash of pu1 => h2
        3. [P2] verifies that pt1 is equal to h2
        """

        p1_public_key_bytes = data[0]
        p1_cipher_text = data[1]
        
        p1_public_key = helper.puk_bytes_to_puk(p1_public_key_bytes)
        p1_public_key_hash_bytes = helper.hash_message(p1_public_key_bytes)

        plaint_text_as_int = helper.rsa_decrypt(p1_cipher_text, p1_public_key.public_numbers().e, p1_public_key.public_numbers().n)
        plain_text_bytes = helper.int_to_bytes(plaint_text_as_int)

        authentic_public_key = True if p1_public_key_hash_bytes == plain_text_bytes else False
        print("\n======> P1 public key verified: {}".format(authentic_public_key))

        # only enter this code block if P1 public key matches attached hash
        if(authentic_public_key == True):
            new_connection = False
            """ Step 2.2 Create P2 private and public key AND create symetric key
            1. [P2] create private key and public key => pr2 & pu2
            2. [P2] create hash on pu2 => h3
            3. [p2] create a symetric key => sk1
            4. [p2] encrypt sk1 and h3 with pu1 to create cipher text => c3
            5. [p2] send pu2 and c3 to P1
            """
            
            rsa_key_length = 512
            rsa_exponent = 65537
            print("\n======> Creating private and public keys with the key length", rsa_key_length, " and the public exponent ", rsa_exponent)
            
            # Generate a private key
            private_key = helper.generate_private_key(rsa_exponent, rsa_key_length)

            # Extract the public key from the private key.
            public_key = private_key.public_key()

            # Convert the keys into bytes
            private_key_bytes = helper.prk_to_bytes(private_key)
            public_key_bytes = helper.puk_to_bytes(public_key)
            print("\n======> (P2 private key)\n\n", private_key_bytes)
            print("\n======> (P2 public key)\n\n", public_key_bytes)

            # Prepare package to send to p1 (key, cipher key, symmetric key iv)
            hash_public_key_bytes = helper.hash_message(public_key_bytes)
            hash_public_key_as_int = helper.bytes_to_int(hash_public_key_bytes)
            print("\n======> Hash of public key created")

            symmetric_key_bytes = helper.aes_get_key_128()
            symmetric_key_as_int = helper.bytes_to_int(symmetric_key_bytes)
            
            symmetric_key_iv_bytes = helper.aes_get_iv()
            symmetric_key_iv_as_int = helper.bytes_to_int(symmetric_key_iv_bytes)
            print("\n======> Symmetric key and iv created")
            
            cipher_public_key_hash_int = helper.rsa_encrypt(hash_public_key_as_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
            print("\n======> Public key hash encrypted using private key and rsa algorithm")
            cipher_symmetric_key_int = helper.rsa_encrypt(symmetric_key_as_int, p1_public_key.public_numbers().e, p1_public_key.public_numbers().n)
            print("\n======> symmetric key encrypted using P1 public key and rsa algorithm")
            cipher_symmetric_key_iv_int = helper.rsa_encrypt(symmetric_key_iv_as_int, p1_public_key.public_numbers().e, p1_public_key.public_numbers().n)
            print("\n======> symmetric key iv encrypted using P1 public key and rsa algorithm")

            # Send response to P1
            package = ([public_key_bytes, cipher_public_key_hash_int, cipher_symmetric_key_int, cipher_symmetric_key_iv_int])
            data = pickle.dumps(package)
            UDPServerSocket.sendto(data, address)
            print("\nsent package. waiting for reply...")
            
            line_is_secure = True

        else:
            #Let user know if the connection is authentic/if the public key match the attached key hash
            online = False
            print("\n###################################################################")
            print("Not Secure: Public key does not match attached hash\n")
            print("P1 plain text: \n{}".format(plain_text_bytes))
            print("P1 pu1 hash: \n{}".format(p1_public_key_hash_bytes))
            print("\n###################################################################")

    # if connection is not new AND  p1's public key is authentic AND the line is secure, send encrypted messages
    elif(authentic_public_key == True and line_is_secure == True):
        # extract iv and cipher text
        p1_cipher_bytes = data[0]

        # decrypt cipher
        plain_text_bytes = helper.aes_decrypt( p1_cipher_bytes, symmetric_key_bytes, symmetric_key_iv_bytes)
        print("\n===================(Message Received)===================")
        print("\n ---- P1 says: {}".format(plain_text_bytes))

        secret_message_bytes = input("\n ---- Enter Secret Message: ").encode()
        cipher = helper.aes_encrypt( secret_message_bytes, symmetric_key_bytes, symmetric_key_iv_bytes)

        package = ([cipher])
        message = pickle.dumps(package)

        UDPServerSocket.sendto(message, address)
        print("\nsent package. waiting for reply...")

    # Conditions not met, end while loop
    else:
        online = False
        print("\n###################################################################")
        print("Line is no longer secure")
        print("\n###################################################################")
