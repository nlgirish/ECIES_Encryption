# ECIES_Encryption
ECIES based encryption algorithm examples. 

In this update I have modified the base package that I got it from the link: http://www.mail-archive.com/openssl-dev@openssl.org/msg28042.html

In this update I have done below changes:
  1. Read private and public EC keys from a certificate and private key in pem format.
  2. Use those keys for encryption and decryption
  3. Client will encrypt a sample message & Server will decrypt the encrypted message

Build and installation steps:
  1. Download the entire directory
  2. Build client and server modules (use 'make' command)
  3. Run server first: ./server
  4. On a separate console, run client: ./client
  5. You can see the message displayed on the server after dycryption
