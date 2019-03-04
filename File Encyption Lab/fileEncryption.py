import os
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# (C, IV)= Myencrypt(message, key):

# In this method, you will generate a 16 Bytes IV, 
# and encrypt the message using the key and IV in CBC mode (AES).  
# You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

def myEncrypt(message, key):


    if(len(key) <32):
        return "Key length is less than the required 32 bits"

    # generate a 16 Bytes IV
    IV = os.urandom(16)

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()


    # Decryption test
    #decryptor = cipher.decryptor()
    #decryptor.update(ct) + decryptor.finalize()

    print(ct)

    

    


def main():

    key = os.urandom(32)
    message = "Hello"

    myEncrypt(message, key)

if __name__ == '__main__':
    main()
