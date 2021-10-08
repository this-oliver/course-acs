# **SSL**

This excercise consists of two parts, In the first section, we create certificates for our Server and Client. In the second section, we create a certificate for another client, Client2, that is signed by ther Server.

## **Section 1: Manually Creating Certificates**

In this excercise, we use certificates to get two entities, [Server](./Server) and [Client](./Client), to communicate securly.

In order to do this, we manually created self-signed certificates for both entities using the OpenSSL terminal commands shown below:

```Bash
# Before running the commands, we bashed into the relevant directory. In this example, we bashed into the Server directory. We repeated this process on the Client directory.

# 1. We created a private key and saved it as 'key.pem'

openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa keygen_bits:2048

# 2. We created certificate signing request and saved it as 'cert.csr'. When configuring the request, we stated that:
#####################################
## country = SV,
## province = Norrbotten,
## city = Lulea,
## org = LTU,
## unit = CSE
## common name = <entity>_LTU (Server_LTU)
## email = <entity>@ltu.se (Server@ltu.se)
## challenger password = password
#####################################

openssl req -new -key key.pem -out cert.csr

# 3. We self signed the certificate with our private key and saved it as 'cert.ctr'

openssl x509 -req  -days 30 -in cert.csr -signkey key.pem -out cert.crt
```

## **Section 2: Signing A Certificate With Another Certificate**

In this section, we follow step 1 and 2 as shown above. The difference is that we do not sign the certificate request with our own private key (self-sign), instead we sign it with another certificate.

```Bash
# For the final step where we sign a certificate request, we bash into the Server directory and run the following command:

openssl x509 -req -days 360 -in ../Client2/cert.csr -CAcreateserial -CA cert.crt -CAkey key.pem -out ../Client2/cert.crt

# In the command above, we take Client2's certificate request `cert.csr` and sign it using the Server's certificate `cert.crt` and it's private key `key.pem`. The result is a signed certificate `cert.crt` which is placed in Client2's directory.

# This certificate will not work with the scripts used in the Section 1 because the signer of Client2's certificate did not have a CA certificate.
```
