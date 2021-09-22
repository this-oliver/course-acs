# **Applied Computer Security**

Course A7010E @ Luleå

## **Lab 1: Network Protocol Analysis**

> Find source code at [./lab_1](./lab_1)

In this lab, we ran a [webserver](./lab_1/webserver.py) and then examined packages sent over the local network protocol using [wireshark](https://www.wireshark.org/), a network protocol analyzer.

## **Lab 2: Encryption**

> Find source code at [./lab_2](./lab_2)

In this lab, we experiemented with different encryption and hash python libraries.

### **Hashing**

In [Hash.py](./lab_2/HASH.py), we looked multiple hash alsorigthms and played around with different plain texts. We even tried out salting the hashes.

### **Symmetric Encryption**

In [AES](./lab_2/AES), we looked at the Advanced Encryption Standard, a symmetric encryption algorithm. We experiemented with the different modes of operation such as [Electronic Block Cipher](./lab_2/AES/ECB.py), [Cipher Block Chaining](./lab_2/AES/CBC.py) and [Counter](./lab_2/AES/CTR.py).

### **Asymmetric Encryption**

In [RSA](./lab_2/RSA), we looked at the RSA asymmetric encryption algorithm and experiemented with the different key lengths.

### **Key Exchange**

In [Key_Exchange](./lab_2/Key_Exchange), we implemented our own version of a secure line of communication where two parties, [P1](./lab_2/Key_Exchange/P1.py) and [P2](./lab_2/Key_Exchange/P2.py), communicate with a symmetric key that they exchange using assymetric keys. The [helper.py](./lab_2/Key_Exchange/helper.py) contains all the encryption algorithms used to implement the secure communication.
