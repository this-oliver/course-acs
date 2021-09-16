#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Sep  7 13:55:46 2021

@author: christer
"""

import hashlib
import os 

def generate_a_salt():
    salt = os.urandom(16)
    str_salt=str(salt)
    encoded_string = str_salt.encode()
    return bytearray(encoded_string) #The salt is returned as a byte_array


message_to_hash=b'security'
salt = generate_a_salt()

print("Message: ", message_to_hash.decode('UTF-8'))

md5_hasher = hashlib.md5(message_to_hash)
print("MD5 hash: ", md5_hasher.hexdigest())

md5_hasher_salt = hashlib.md5(salt)
print("MD5 hash salt: ", md5_hasher_salt.hexdigest())

md5_hasher_res = hashlib.md5(message_to_hash+salt)
print("MD5 hash result: ", md5_hasher_res.hexdigest())

"""
sha1_hasher= hashlib.sha1(message_to_hash)
print("SHA1 hash: ", sha1_hasher.hexdigest())

sha256_hasher= hashlib.sha256(message_to_hash)
print("SHA256 hash: ",sha256_hasher.hexdigest())
"""