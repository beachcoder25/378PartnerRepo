import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
import json

# Constants


FILE_PATH = "C:/Users/corni/Desktop/ransomTest"
PUB_FOUND = False
PRIV_FOUND = False



def findKey(filePath):
    
    privFound = 1
    pubFound = 1

    pubKey = "/public.pem"
    privKey = "/private.pem"

    pubFilePath = filePath + pubKey
    privFilePath = filePath + privKey

    pubExists = os.path.isfile(pubFilePath)
    privExists = os.path.isfile(privFilePath)

    # Check if public key exists

    if pubExists:
        PUB_FOUND = 1
        print("Found public key! \nFilePath: " + pubFilePath)
        

    elif (pubExists == False):
        PUB_FOUND = 0
        print("Did not find public key!\nBoolean value: " + str(PUB_FOUND))

    # Check if private key exists 

    if privExists:
        PRIV_FOUND = 1
        print("\nFound public key! \nFilePath: " + privFilePath)
        

    elif (pubExists == False):
        PRIV_FOUND = 0
        print("\nDid not find public key!\nBoolean value: " + str(PRIV_FOUND))      

    print(" ")  


def fileFindTest():

    
    print("Running Test")
    findKey(FILE_PATH)

fileFindTest()



# mainMACDesktop()

# if __name__ == '__main__':
#     main()