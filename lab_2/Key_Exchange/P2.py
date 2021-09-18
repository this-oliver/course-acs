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
import pickle
import acs_tool

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

# Wait for incomming messages
while(online):
    newPackage = UDPServerSocket.recvfrom(bufferSize)
    address = newPackage[1]
    print("\nP1's Address is:{}".format(address))

    data = pickle.loads(newPackage[0])

    print("\nLine Secure: {}".format(line_is_secure))
    print("\nAuthentic P1 Key: {}".format(authentic_public_key))

    # if connection is new, verify public key
    if(new_connection == True):
      """ Step 2.1 Verify P1's public key
      1. [P2] decrypt cipher text (c1) with P1's pu1 => pt1 (this is essentially h1)
      2. [P2] create a hash of pu1 => h2
      3. [P2] verifies that pt1 is equal to h2
      """
      
      print("\n [1] Veryifying public key...")

      p1_public_key_bytes = data[0]
      p1_cipher_text = data[1]

      p1_public_key = acs_tool.puk_bytes_to_puk(p1_public_key_bytes)

      plaint_text_as_int = acs_tool.rsa_decrypt(p1_cipher_text, p1_public_key.public_numbers().e, p1_public_key.public_numbers().n)
      plain_text_bytes = acs_tool.int_to_bytes(plaint_text_as_int)

      p1_public_key_hash = acs_tool.hash_message(p1_public_key_bytes)
      p1_public_key_hash_bytes = p1_public_key_hash.digest()

      authentic_public_key = True if p1_public_key_hash_bytes == plain_text_bytes else False
      print("\nIs P1 public key valid: {}".format(authentic_public_key))

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

        print("\n Creating private and public keys..\n")
        
        rsa_key_length = 512
        rsa_exponent = 65537
        print("\n P2 key length is", rsa_key_length, " and the public exponent is ", rsa_exponent, "\n")

        # Generate a private key
        private_key = acs_tool.generate_private_key(rsa_exponent, rsa_key_length)

        # Extract the public key from the private key.
        public_key = private_key.public_key()

        # Convert the keys into bytes
        private_key_bytes = acs_tool.prk_to_bytes(private_key)
        public_key_bytes = acs_tool.puk_to_bytes(public_key)
        print("\n ======> P2 private key\n\n", private_key_bytes)
        print("\n ======> P2 public key\n\n", public_key_bytes)

        ## Prepare package
        hash_public_key = acs_tool.hash_message(public_key_bytes)
        hash_public_key_as_int = acs_tool.bytes_to_int(hash_public_key.digest())
        print("\n ======> P2 public key hash\n\n", hash_public_key_as_int)

        cipher_public_key_hash_int = acs_tool.rsa_encrypt(hash_public_key_as_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
        print("\n ======> P2 hash cipher\n\n", cipher_public_key_hash_int)
        
        symmetric_key_bytes = acs_tool.aes_get_key_128()
        symmetric_key_as_int = acs_tool.bytes_to_int(symmetric_key_bytes)
        cipher_symmetric_key_int = acs_tool.rsa_encrypt(symmetric_key_as_int, p1_public_key.public_numbers().e, p1_public_key.public_numbers().n)
        print("\n ======> P2 sk cipher\n\n", cipher_symmetric_key_int)

        symmetric_key_iv_bytes = acs_tool.aes_get_iv()
        symmetric_key_iv_as_int = acs_tool.bytes_to_int(symmetric_key_iv_bytes)
        cipher_symmetric_key_iv_int = acs_tool.rsa_encrypt(symmetric_key_iv_as_int, p1_public_key.public_numbers().e, p1_public_key.public_numbers().n)
        print("\n ======> P2 sk iv cipher\n\n", cipher_symmetric_key_int)

        package = ([public_key_bytes, cipher_public_key_hash_int, cipher_symmetric_key_int, cipher_symmetric_key_iv_int])
        data = pickle.dumps(package)

        #Send response to P1
        UDPServerSocket.sendto(data, address)
        print("\n ======> P2 message sent\n\n", package)
        line_is_secure = True

      else:
        online = False
        print("\nNot Secure: Public key does not match attached hash\n")
        print("\nP1 plain text: \n{}".format(plain_text_bytes))
        print("\nP1 pu1 hash: \n{}".format(p1_public_key_hash_bytes))

    # if connection is not new AND  p1's public key is authentic AND the line is secure, send encrypted messages
    elif(authentic_public_key == True and line_is_secure == True):
      # extract iv and cipher text
      p1_cipher = data[0]
      p1_iv = data[1]

      # decrypt cipher
      plain_text_bytes = acs_tool.aes_decrypt(p1_cipher, symmetric_key_bytes, symmetric_key_iv_bytes)
      print("\nP1 says: \n{}".format(plain_text_bytes))

      secret_message_bytes = input("\nEnter secret message: ").encode()
      cipher = acs_tool.aes_encrypt(secret_message_bytes, symmetric_key_bytes, symmetric_key_iv_bytes)

      package = ([cipher])
      message = pickle.dumps(package)

      UDPServerSocket.sendto(message, address)
      print("\n ======> P2 message sent\n\n", message)
    
    # something went wrong
    else:
      online = False
      print("\nLine is no longer secure\n")