# key exhange 101

**Part 1: P1 creates their private and public keys and send a package (their public key and a hash of their public key) to P2**

1. [P1] create private key and public key => pr1 & pu1
2. [P1] create hash on pu1 => h1
3. [p1] encrypts the hash with their private key to create a cipher text => c1
4. [P1] send the pu1 and c1 to P2

**Part 2.1: P2 verifies P1's public key pu1**

1. [P2] decrypt cipher text (c1) with P1's pu1 => pt1 (this is essentially h1)
2. [P2] create a hash of pu1 => h2
3. [P2] verifies that pt1 is equal to h2

**Part 2.2: P2 creates their private and public key and a symmetric key and sends a package (their public key, a hash of the public key and a cipher text with symetric key) to P1**

1. [P2] create private key and public key => pr2 & pu2
2. [P2] create hash on pu2 => h3
3. [p2] create a symetric key => sk1
4. [p2] encrypt sk1 and h3 with pu1 to create cipher text => c3
5. [p2] send pu2 and c3 to P1

**Part 3: P1 verifies P2's public key**

1. [P1] decrypts c3 with their pr1 => pt2 (sk1 + h3)
2. [p1] create a hash of pu2 => h4
3. [P1] verifies h3 is equal to h4

**Part 4.1: P1 sends encrypted message to P2**

1. [P1] encrypts message with sk1 => c4
2. [P1] sends message to P2

**Part 4.2: P2 sends encrypted message to P1**

1. [P1] decrypts c4 with sk1 => pt3
2. [P1] encrypts a reply message with sk1 => c5
3. [P1] sends message to P1

**Part 4.3: P1 sends encrypted message to P2**

1. [P1] decrypts c5 with sk1 => pt4
2. [P1] encrypts a reply message with sk1 => c6
3. [P1] sends message to P1

*Part 4 goes on and on and ...*
