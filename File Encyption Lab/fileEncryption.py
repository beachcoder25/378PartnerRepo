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
        return "ERROR: Key length is less than the required 32 bits"

    # generate a 16 Bytes IV
    # IV is used so if we encrypt an identical piece of data that it 
    # comes out encrypted different each time its encrypted
    
    backend = default_backend()
    IV = os.urandom(16)

    
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)    #Cipher objects combine an algorithm such as AES with a mode like CBC
                                                                            # Notice we pass in the (key) to our AES argument, and (IV) to our CBC mode
    encryptor = cipher.encryptor()
    C = encryptor.update(message) + encryptor.finalize()                    # Cipher text = encypt message + finalize encryption
                                                                            # Message now encrypted
    print(C)

    # Decryption test
    #decryptor = cipher.decryptor()
    #decryptor.update(C) + decryptor.finalize()

    #print(C)

    

    


def main():

    key = os.urandom(32)
    message = b"a secret message"

    myEncrypt(message, key)

if __name__ == '__main__':
    main()
