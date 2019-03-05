import os
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

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

    # USE PKCS7 TO PAD!!!
    # https://cryptography.io/en/latest/hazmat/primitives/padding/
    padder = padding.PKCS7(128).padder()
    padMessage = padder.update(message)
    print(padMessage)

    padMessage += padder.finalize()
    print(padMessage)
    
    
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
    message1 = b"a secret message"
    message = b"sixteen  letters"
    

    # padder = padding.PKCS7(128).padder()
    # padMessage = padder.update(b"Hello")
    # print(padMessage)

    # padMessage += padder.finalize()
    # print(padMessage)


    myEncrypt(message, key)

if __name__ == '__main__':
    main()
