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


""" Step 2.1
1. [P2] decrypt cipher text (c1) with P1's pu1 => pt1 (this is essentially h1)
2. [P2] create a hash of pu1 => h2
3. [P2] verifies that pt1 is equal to h2
"""

print("\nP2 is up running and ready to go!")
msgFromServer = "\nHi P1, Applied Computer Science P2 here, I hope all is secured on your side."
bytesToSend = str.encode(msgFromServer)

online = True
symmetric_key = None
new_connection = True
line_is_secure = False
authentic_public_key = False

# Wait for incomming calls, any one out there? Hopefully P1.
while(online):
    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)
    address = bytesAddressPair[1]
    sendersIP  = "P1's Address is:{}".format(address)
    print(sendersIP)

    data = pickle.loads(bytesAddressPair[0])

    if(new_connection == True):
      p1_public_key_bytes = data[0]
      p1_cipher_text = data[1]
      pk = "\nP1 key: \n{}".format(p1_public_key_bytes)
      ct = "\nP1 cipher: \n{}".format(p1_cipher_text)
      print(pk)
      print(ct)

      p1_public_key = acs_tool.puk_bytes_to_puk(p1_public_key_bytes)
      p1_public_key_exponent = p1_public_key.public_numbers().e
      p1_public_key_number = p1_public_key.public_numbers().n

      plaint_text_as_int = acs_tool.rsa_decrypt(p1_cipher_text, p1_public_key_exponent, p1_public_key_number)
      pt = "\nP1 plain text: \n{}".format(plaint_text_as_int)
      print(pt)

      p1_public_key_hash = acs_tool.hash_message(p1_public_key_bytes)
      p1_public_key_hash_as_int = acs_tool.bytes_to_int(p1_public_key_hash.digest())
      hash = "\nP1 pu1 hash: \n{}".format(p1_public_key_hash_as_int)
      print(hash)

      p1_public_key_hash = acs_tool.int_to_bytes(p1_public_key_hash_as_int)
      plain_text = acs_tool.int_to_bytes(plaint_text_as_int)

      authentic_public_key = True if p1_public_key_hash == plain_text else False
      auth_msg = "\nIs P1 public key valid: {}".format(authentic_public_key)
      print(auth_msg)

      # only enter this code block if P1 public key matches attached hash
      if(authentic_public_key == True):
        new_connection = False

        """ Step 2.2
        1. [P2] create private key and public key => pr2 & pu2
        2. [P2] create hash on pu2 => h3
        3. [p2] create a symetric key => sk1
        4. [p2] encrypt sk1 and h3 with pu1 to create cipher text => c3
        5. [p2] send pu2 and c3 to P1
        """

        rsa_key_length = 512
        rsa_exponent = 65537

        print("\n === P2 key length ===\n", rsa_key_length)
        print("\n === P2 public exponent ===\n", rsa_exponent)

        # Generate a private key.
        private_key = acs_tool.generate_private_key(rsa_exponent, rsa_key_length)
        private_key_exponent = private_key.private_numbers().d
        private_key_number = private_key.private_numbers().public_numbers.n

        # Extract the public key from the private key.
        public_key = private_key.public_key()
        public_key_exponent = public_key.public_numbers().e
        public_key_number = public_key.public_numbers().n

        # Convert the keys into bytes
        private_key_bytes = acs_tool.prk_to_bytes(private_key)
        public_key_bytes = acs_tool.puk_to_bytes(public_key)

        print("\n === P2 private key ===\n\n", private_key_bytes)
        print("\n === P2 public key ===\n\n", public_key_bytes)

        ## Prepare package

        hash_public_key = acs_tool.hash_message(public_key_bytes)
        hash_as_int = acs_tool.bytes_to_int(hash_public_key.digest())

        print("\n === P2 public key hash ===\n\n", hash_as_int)

        hash_cipher_text = acs_tool.rsa_encrypt(hash_as_int, private_key_exponent, private_key_number)
        print("\n === P2 hash cipher ===\n\n", hash_cipher_text)
        
        symmetric_key = acs_tool.aes_get_key_128()
        symmetric_key_as_int = acs_tool.bytes_to_int(symmetric_key)
        symmetric_key_cipher_text = acs_tool.rsa_encrypt(symmetric_key_as_int, private_key_exponent, private_key_number)
        print("\n === P2 sk cipher ===\n\n", symmetric_key_cipher_text)

        package = ([public_key_bytes, hash_cipher_text, symmetric_key_cipher_text])
        data = pickle.dumps(package)

        #Send response to P1
        UDPServerSocket.sendto(data, address)
        print("\n === P2 message sent ===\n\n", data)

        line_is_secure = True


    # only after establishing a secure line
    elif(line_is_secure == True and authentic_public_key == True):
      bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)  
      data = pickle.loads(bytesAddressPair[0])

      # extract iv and cipher text
      p1_cipher = data[0]
      p1_iv = data[1]

      # decrypt cipher
      plain_text = acs_tool.aes_decrypt(p1_cipher, symmetric_key, p1_iv)
      secret = plain_text
      print("\nP1 says: \n{}".format(secret))

      user_input = input("\nEnter Secret Message: ").encode()

      iv = acs_tool.aes_get_iv()
      cipher = acs_tool.aes_encrypt(user_input, symmetric_key, iv)

      package = ([cipher, iv])
      message = pickle.dumps(package)

      UDPServerSocket.sendto(message, address)
      print("\n === P2 message sent ===\n\n", message)
    
    # something went wrong
    else:
      online = False
      print("\nLine is no longer secure\n")