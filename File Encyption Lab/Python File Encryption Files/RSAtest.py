import os

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives import hashes, serialization, hmac, padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as PADDING
import fileEncryption as fE 

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
# CWD = getcwd()
# FILE_PATH = f'{CWD}/ransomTest'



BACKEND = default_backend()
pubKey = "/publicTest9.pem"
privKey = "/privateTest9.pem"
pubFilePath = FILE_PATH + pubKey
privFilePath = FILE_PATH + privKey
PRIV_PASS = os.urandom(PASS_SIZE) # In bytes!!!
ENC_KEY = None 
HMAC_KEY = None


def keyCheck():
    

    pubExists = os.path.isfile(pubFilePath)
    privExists = os.path.isfile(privFilePath)

    


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
            format = serialization.PrivateFormat.PKCS8, 
            encryption_algorithm=serialization.NoEncryption())
        

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

    return pubFilePath, privFilePath

        


def MyRSAEncrypt(filepath, RSA_Publickey_filepath):

    # Return needed parameters
    C, IV, tag, EncKey, HMACKey, ext = fE.MyFileEncryptMAC(filepath)

    


    # Get file paths for keys
    

    # Initialize RSA public key encryption object
    try:
        with open(RSA_Publickey_filepath, 'rb') as pubKey:
            publicPEM = serialization.load_pem_public_key(pubKey.read(), backend = BACKEND)
            #print("Public key: " + str(publicPEM))
    
    except FileNotFoundError as e:
        print('Could not locate a public key')
        exit(1)

    # Encrypt key variable in OAEP padding mode
    concatKey = EncKey + HMACKey

    RSACipher = publicPEM.encrypt(
        concatKey,
        PADDING.OAEP(mgf = PADDING.MGF1(algorithm = hashes.SHA256()), 
        algorithm = hashes.SHA256(), 
        label = None))

    return(RSACipher, C, IV, tag, ext, HMACKey)



def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath):

    # Open private key file to instantiate a private key decryption object

    print(RSA_Privatekey_filepath)
    try:
        with open(RSA_Privatekey_filepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password = None, backend = BACKEND)
    
    except FileNotFoundError as e:
        print('No private key found')
        exit(1)

    print("Private key WAS found!")

    # Use the private key object to decrypt

    keys = private_key.decrypt(RSACipher, PADDING.OAEP(mgf=PADDING.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Encryptionn key and HMA C keys are the same size, split the data in half to retrieve both keys

   
    encKey, HMACkey = keys[:24], keys[24:]
    print("\n\n\n\n")
    print("C in RSADecrypt")
    print(C[0:10])

    h = hmac.HMAC(HMACkey, hashes.SHA256(), backend=default_backend())
    h.update(C) # This should update the bytes with the HMAC
    receiverTag = h.finalize()
    print("TAGS:")
    print(receiverTag)


    M = fE.MydecryptMAC(C, IV, receiverTag, encKey, HMACkey, ext)
    

    return M





#--------------------------------------------------------
# MAIN
#--------------------------------------------------------


def main():

   
    # print("Running Test")
    # keyCheck()

    print("WHAT")


    

    desktopFilePath = "C:/Users/corni/Desktop/ransomTest/files/panda.jpg"

    #C, IV, tag, EncKey, HMACKey, ext = fE.MyFileEncryptMAC(desktopFilePath)
    # return(RSACipher, C, IV, tag, ext)

    pubFilePath, privFilePath = keyCheck()


    RSACipher, C, IV, tag, ext, HMACKey = MyRSAEncrypt(desktopFilePath, pubFilePath)

    print("C after creation")
    print(C[0:10])

    

    print("Writing encrypted File")
    
    # DESKTOP
    file = open("C:/Users/corni/Desktop/ransomTest/files/testfile.txt","wb") # wb for writing in binary mode 

 
    file.write(C) # Writes cipher byte-message into text file
    file.close() 

    encryptedFilepath = "C:/Users/corni/Desktop/ransomTest/files/testfile.txt"

    # Laptop
    # encryptedFilepath = "C:/Users/Jonah/Desktop/378Lab/testfile.txt"


    # Message verification
    print("\nVerifying message!!:")
    
    print("TEST")
    M = MyRSADecrypt(RSACipher, C, IV, tag, ext, privFilePath)

        
    print("Writing decrypted File")

    # DESKTOP
    file = open("C:/Users/corni/Desktop/ransomTest/files/outputfileYYY.jpg","wb") # wb for writing in binary mode

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/outputfile.jpg","wb") # wb for writing in binary mode
    
    file.write(M) # Writes cipher byte-message into text file
    file.close() 

    


if __name__ == '__main__':
    main()