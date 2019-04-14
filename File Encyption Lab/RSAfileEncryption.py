import os

# May not need
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization

# Definitely need
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import json

# Constants


FILE_PATH = "C:/Users/corni/Desktop/ransomTest"
PUB_FOUND = False
PRIV_FOUND = False
PASS_SIZE = 10



def findKeys(filePath):
    
    privFound = 1
    pubFound = 1

    pubKey = "/public2.pem"
    privKey = "/private2.pem"

    pubFilePath = filePath + pubKey
    privFilePath = filePath + privKey

    pubExists = os.path.isfile(pubFilePath)
    privExists = os.path.isfile(privFilePath)

    PRIV_PASS = os.urandom(PASS_SIZE) # In bytes!!!
    # print(type(PRIV_PASS))
    # print(PRIV_PASS)


    # Check if private key exists 

    if privExists:
        PRIV_FOUND = 1
        print("\nFound public key! \nFilePath: " + privFilePath)
        

    elif (pubExists == False):
        PRIV_FOUND = 0
        print("\nDid not find public key!\nBoolean value: " + str(PRIV_FOUND))     

        # generate private key

        private_key = rsa.generate_private_key(
            public_exponent = 65537, 
            key_size = 2048, 
            backend = default_backend()) 

        # Serialize private key 

        private_pem = private_key.private_bytes(
            encoding = serialization.Encoding.PEM, 
            format = serialization.PrivateFormat.TraditionalOpenSSL, 
            encryption_algorithm=serialization.BestAvailableEncryption(PRIV_PASS))
        
        with open(FILE_PATH + privKey, 'wb') as f:
            f.write(private_pem)

        # Serialize public

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(encoding = serialization.Encoding.PEM, format = serialization.PublicFormat.SubjectPublicKeyInfo)
        
        with open(FILE_PATH + pubKey, 'wb') as f:
            f.write(public_pem)

        # Double-check that public key now exists
        if pubExists:
            PUB_FOUND = 1
            print("Found public key! \nFilePath: " + pubFilePath)
            

        elif (pubExists == False):
            PUB_FOUND = 0
            print("Did not find public key!\nBoolean value: " + str(PUB_FOUND))

            # generate private key
    
    # Check if public key exists

    # if pubExists:
    #     PUB_FOUND = 1
    #     print("Found public key! \nFilePath: " + pubFilePath)
        

    # elif (pubExists == False):
    #     PUB_FOUND = 0
    #     print("Did not find public key!\nBoolean value: " + str(PUB_FOUND))

        # generate private key


        
        

    


#     print(" ")  


def fileFindTest():

    
    print("Running Test")
    findKeys(FILE_PATH)


fileFindTest()



# mainMACDesktop()

# if __name__ == '__main__':
#     main()