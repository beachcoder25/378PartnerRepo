import os
<<<<<<< HEAD
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
=======

# May not need
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac, serialization

# Definitely need
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

>>>>>>> Jonah
import json

# Constants


FILE_PATH = "C:/Users/corni/Desktop/ransomTest"
PUB_FOUND = False
PRIV_FOUND = False
<<<<<<< HEAD



def findKey(filePath):
=======
PASS_SIZE = 10



def findKeys(filePath):
>>>>>>> Jonah
    
    privFound = 1
    pubFound = 1

<<<<<<< HEAD
    pubKey = "/public.pem"
    privKey = "/private.pem"
=======
    pubKey = "/public3.pem"
    privKey = "/private3.pem"
>>>>>>> Jonah

    pubFilePath = filePath + pubKey
    privFilePath = filePath + privKey

    pubExists = os.path.isfile(pubFilePath)
    privExists = os.path.isfile(privFilePath)

<<<<<<< HEAD
    # Check if public key exists

    if pubExists:
        PUB_FOUND = 1
        print("Found public key! \nFilePath: " + pubFilePath)
        

    elif (pubExists == False):
        PUB_FOUND = 0
        print("Did not find public key!\nBoolean value: " + str(PUB_FOUND))
=======
    PRIV_PASS = os.urandom(PASS_SIZE) # In bytes!!!
    # print(type(PRIV_PASS))
    # print(PRIV_PASS)

>>>>>>> Jonah

    # Check if private key exists 

    if privExists:
        PRIV_FOUND = 1
<<<<<<< HEAD
        print("\nFound public key! \nFilePath: " + privFilePath)
=======
        print("\nFound private key! \nFilePath: " + privFilePath)
>>>>>>> Jonah
        

    elif (pubExists == False):
        PRIV_FOUND = 0
<<<<<<< HEAD
        print("\nDid not find public key!\nBoolean value: " + str(PRIV_FOUND))      

    print(" ")  
=======
        print("\nDid not find private key!\nBoolean value: " + str(PRIV_FOUND))     

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
>>>>>>> Jonah


def fileFindTest():

    
    print("Running Test")
<<<<<<< HEAD
    findKey(FILE_PATH)
=======
    findKeys(FILE_PATH)

>>>>>>> Jonah

fileFindTest()



# mainMACDesktop()

# if __name__ == '__main__':
#     main()