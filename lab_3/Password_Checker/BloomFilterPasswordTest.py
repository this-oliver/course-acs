#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Sep 27 14:07:57 2021

The BloomFilter class is downloaded from https://www.geeksforgeeks.org/bloom-filters-introduction-and-python-implementation/
 / Christer

"""

import math
import mmh3
from bitarray import bitarray
 
 
class BloomFilter(object):
 
    '''
    Class for Bloom filter, using murmur3 hash function
    '''
 
    def __init__(self, items_count, fp_prob):
        '''
        items_count : int
            Number of items expected to be stored in bloom filter
        fp_prob : float
            False Positive probability in decimal
        '''
        # False possible probability in decimal
        self.fp_prob = fp_prob
 
        # Size of bit array to use
        self.size = self.get_size(items_count, fp_prob)
 
        # number of hash functions to use
        self.hash_count = self.get_hash_count(self.size, items_count)
 
        # Bit array of given size
        self.bit_array = bitarray(self.size)
 
        # initialize all bits as 0
        self.bit_array.setall(0)
 
    def add(self, item):
        '''
        Add an item in the filter
        '''
        digests = []
        for i in range(self.hash_count):
 
            # create digest for given item.
            # i work as seed to mmh3.hash() function
            # With different seed, digest created is different
            digest = mmh3.hash(item, i) % self.size
            digests.append(digest)
 
            # set the bit True in bit_array
            self.bit_array[digest] = True
 
    def check(self, item):
        '''
        Check for existence of an item in filter
        '''
        for i in range(self.hash_count):
            digest = mmh3.hash(item, i) % self.size
            if self.bit_array[digest] == False:
 
                # if any of bit is False then,its not present
                # in filter
                # else there is probability that it exist
                return False
        return True
 
    @classmethod
    def get_size(self, n, p):
        '''
        Return the size of bit array(m) to used using
        following formula
        m = -(n * lg(p)) / (lg(2)^2)
        n : int
            number of items expected to be stored in filter
        p : float
            False Positive probability in decimal
        '''
        m = -(n * math.log(p))/(math.log(2)**2)
        return int(m)
 
    @classmethod
    def get_hash_count(self, m, n):
        '''
        Return the hash function(k) to be used using
        following formula
        k = (m/n) * lg(2)
 
        m : int
            size of bit array
        n : int
            number of items expected to be stored in filter
        '''
        k = (m/n) * math.log(2)
        return int(k)



# Add the false positive probability value
p = 0.001

# Read known passwords from your textfile
# (source for KnownPasswords.txt: https://github.com/danielmiessler/SecLists/blob/master/Passwords/2020-200_most_used_passwords.txt)
passwdFile = open("KnownPasswords.txt","r")
knownPasswords = passwdFile.read().splitlines()

print("{}\n".format(knownPasswords))

# Create the Bloomfilter and the structure of it
bloomf = BloomFilter(knownPasswords.__len__(),p)
print("Size of bit array:{}\n".format(bloomf.size))
print("False positive Probability:{}\n".format(bloomf.fp_prob))
print("Number of hash functions:{}\n".format(bloomf.hash_count))

# Add the password read from the file to the filter
for item in knownPasswords:
    bloomf.add(item)

while True:
    # Enter the password to check
    checkPassword = input("Enter password to check and press Enter: \n")
 
    # Let's see what the Bloomfilter says weather the password might be known.
    if not bloomf.check(checkPassword):
        print("'{}' is definitely not present!\n".format(checkPassword))
    else:
        print("'{}' is probably present acccording to the Bloomfilter!\n".format(checkPassword))
        if checkPassword not in knownPasswords:
            print("But that is false, it does no exist so this is a false positive\n")
  
   