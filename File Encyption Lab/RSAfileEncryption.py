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



def findKeys(filePath):
    
    privFound = 1
    pubFound = 1

    pubKey = "/public.pem"
    privKey = "/private.pem"

    pubFilePath = filePath + pubKey
    privFilePath = filePath + privKey

    pubExists = os.path.isfile(pubFilePath)
    privExists = os.path.isfile(privFilePath)


    # Check if private key exists 

    if privExists:
        PRIV_FOUND = 1
        print("\nFound public key! \nFilePath: " + privFilePath)
        

    elif (pubExists == False):
        PRIV_FOUND = 0
        print("\nDid not find public key!\nBoolean value: " + str(PRIV_FOUND))     

        # generate private key

        private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend()) 

        # Serialize key 

        private_pem = private_key.private_bytes(encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm = serialization.NoEncryption())
    
    # Check if public key exists

    if pubExists:
        PUB_FOUND = 1
        print("Found public key! \nFilePath: " + pubFilePath)
        

    elif (pubExists == False):
        PUB_FOUND = 0
        print("Did not find public key!\nBoolean value: " + str(PUB_FOUND))

        # generate private key


        
        

    


    print(" ")  


def fileFindTest():

    
    print("Running Test")
    findKeys(FILE_PATH)

fileFindTest()



# mainMACDesktop()

# if __name__ == '__main__':
#     main()