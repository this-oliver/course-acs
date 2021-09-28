# **Lab 2**

In this lab, we experiemented with different encryption and hash python libraries.

## **Hashing**

In [Hash.py](./Hash.py), we looked multiple hash alsorigthms and played around with different plain texts. We even tried out salting the hashes.

## **Symmetric Encryption**

In [AES](./AES), we looked at the Advanced Encryption Standard, a symmetric encryption algorithm. We experiemented with the different modes of operation such as [Electronic Block Cipher](./AES/ECB.py), [Cipher Block Chaining](./AES/CBC.py) and [Counter](./AES/CTR.py).

## **Asymmetric Encryption**

In [RSA](./RSA), we looked at the RSA asymmetric encryption algorithm and experiemented with the different key lengths.

## **Key Exchange**

In [Key_Exchange](./Key_Exchange), we implemented our own version of a secure line of communication where two parties, [P1](./Key_Exchange/P1.py) and [P2](./Key_Exchange/P2.py), communicate with a symmetric key that they exchange using assymetric keys. The [helper.py](./Key_Exchange/helper.py) contains all the encryption algorithms used to implement the secure communication.
