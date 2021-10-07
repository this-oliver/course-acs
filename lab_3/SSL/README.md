# **SSL**

In this excercise, we use certificates to get two entities, [Server](./Server) and [Client](./Client), to communicate securly.

In order to do this, we manually created self-signed certificates for both entities using the OpenSSL terminal commands shown below:

```Bash
# Before running the commands, we bashed into the relevant directory. In this example, we bashed into the Server directory. We repeated this process on the Client directory.

# 1. We created a private key and saved it as 'key.pem'

openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa keygen_bits:2048

# 2. We created certificate signing request and saved it as 'cert.csr'. When configuring the request, we stated that:
# country = SV,
# province = Norrbotten,
# city = Lulea,
# org = LTU,
# unit = CSE
# common name = <entity>_LTU (Server_LTU)
# email = <entity>@ltu.se (Server@ltu.se)
# challenger password = password

openssl req -new -key key.pem -out cert.csr

# 3. We self signed the certificate with our private key and saved it as 'cert.ctr'

openssl x509 -req  -days 30 -in cert.csr -signkey key.pem -out cert.crt
```
