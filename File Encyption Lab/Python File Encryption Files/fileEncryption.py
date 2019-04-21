import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
import json

# Constants

IV_SIZE = 16
PAD_SIZE = 128
HMAC_KEY = 16
HMAC_KEY_LEN = len(str(HMAC_KEY))
KEY_SIZE = 32
ENC_KEY_SIZE = 32
FILE_PATH = "C:/Users/corni/Desktop/ransomTest"


# Encrypt message using AES, must pad message, and assign proper cipher mode (AES-CBC mode)

def myEncrypt(message, key):

    if(len(key) < 32): # Exception if key is not proper size
        raise Exception('Key length is less than the required 32 bits')
   
    backend = default_backend()
    IV = os.urandom(IV_SIZE) 


    # Pad using PKCS7 so each block is 128

    padder = padding.PKCS7(PAD_SIZE).padder()
    padMessage = padder.update(message)
    padMessage += padder.finalize()


    # Cipher objects combine an algorithm such as AES with a mode like CBC  

    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)                                                                        
    encryptor = cipher.encryptor()
    C = encryptor.update(padMessage) + encryptor.finalize()                    

    return(C,IV)


# Encrypt file by reading photo bits into cvariable, call myEncrypt function, return values

def myFileEncrypt(filepath):

    key = os.urandom(KEY_SIZE) # 32 byte key
    
    # Read file as bits into variable
    with open(filepath, "rb") as ext: # Open file
        photoBits = base64.b64encode(ext.read()) # Read bits into variable

    C, IV = myEncrypt(photoBits, key)
    
    return(C, IV, key, ext)


# Encyrption using an HMAC, encrypt THEN MAC, h is an HMAC object that is stored in the tag variable

def MyencryptMAC(message, EncKey, HMACKey):

    C, IV = myEncrypt(message, EncKey)
    
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend()) # h is HMAC object, combines key and cipherText w/ .update()
    h.update(C) 

    tag = h.finalize() # For comparison with receiver
     
    return(C, IV, tag)


# Decrypt HMAC, authenticate tags before decrypting as normal

def MydecryptMAC(C, IV, tag, EncKey, HMACKey, encryptedFilepath):
    
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C) # This should update the bytes with the HMAC
    receiverTag = h.finalize()

    # Message autheticated

    if(receiverTag ==  tag):
        print("Tags are equal")
        M = myFileDecrypt(EncKey, IV, encryptedFilepath)
    
    # Message NOT autheticated

    else:
        raise Exception("Error: Tags not equal")
        
    return M


# Takes input file and encrypts with HMAC verification

def MyFileEncryptMAC(filepath):

    HMACKey = os.urandom(HMAC_KEY) # Generate 16 Byte key
    EncKey = os.urandom(ENC_KEY_SIZE) # Generate 32 Byte key
    
    with open(filepath, "rb") as ext: # Open file
        photoBits = b''.join(ext.readlines()) 

    C, IV, tag = MyencryptMAC(photoBits, EncKey, HMACKey)
    
    return(C, IV, tag, EncKey, HMACKey, ext)


# Takes a ciphertext and returns unpadded original message

def myDecrypt(C, IV, key):


    if(len(key) < 32):
        raise Exception('Key length is less than the required 32 bits')
    
    # Reverse of encyrption

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend) 
    decryptor = cipher.decryptor()

    M = decryptor.update(C) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()

    # MISTAKE
    # Kept getting invalid padding bytes error, did unpadder.update(C) w/ original ciphertext Not the decrypted text 
    unpaddedMessage = unpadder.update(M) + unpadder.finalize()

    return unpaddedMessage


# Decrypt file with local functions

def myFileDecrypt(key, IV, inputFilepath):

    # Read encypted data back
    with open(inputFilepath, "rb") as ext: # Open file

        # MISTAKE, was using below line to read in as a string
        encryptedPhotoString = b''.join(ext.readlines())                        

    M = myDecrypt(encryptedPhotoString, IV, key)
    
    return M


def mainMACDesktop():
    
    #JSON Attempt
    # JSONfile = "data.json"
    data = {}
    # filepath = "C:/Users/corni/Desktop/JSON.txt" # This the file you are trying to encrypt

    desktopFilePath = "C:/Users/corni/Desktop/panda.jpg"
    
    
    # Desktop
    C, IV, tag, EncKey, HMACKey, ext = MyFileEncryptMAC(desktopFilePath)

    # data[filepath] = { # Store in JSON so you can read out for decryption
    #     "C" : str(C),
    #     "IV" : str(IV),
    #     "tag" : str(tag),
    #     "EncKey": str(EncKey),
    #     "HMACKey" : str(HMACKey),
    #     "ext" : ext
    # }

    # Store encrypted data in a text file
    print("Writing encrypted File")
    
    # DESKTOP
    file = open("C:/Users/corni/Desktop/testfile.txt","wb") # wb for writing in binary mode 

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/testfile.txt","wb") # wb for writing in binary mode
    
    file.write(C) # Writes cipher byte-message into text file
    file.close() 
   
    # Desktop
    encryptedFilepath = "C:/Users/corni/Desktop/testfile.txt"

    # Laptop
    # encryptedFilepath = "C:/Users/Jonah/Desktop/378Lab/testfile.txt"


    # Message verification
    print("\nVerifying message:")
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C)
    receiverTag = h.finalize()

    M = MydecryptMAC(C, IV, tag, EncKey, HMACKey, encryptedFilepath)

        
    print("Writing decrypted File")

    # DESKTOP
    file = open("C:/Users/corni/Desktop/outputfileYYY.jpg","wb") # wb for writing in binary mode

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/outputfile.jpg","wb") # wb for writing in binary mode
    
    file.write(M) # Writes cipher byte-message into text file
    file.close() 







def mainNoMAC():

    # File path for desktop
    desktopFilePath = "C:/Users/corni/Desktop/panda.jpg"
 
    C, IV, key, ext = myFileEncrypt(desktopFilePath)

    # Store encrypted data in a text file
    print("Writing encrypted File")
    
    # DESKTOP
    file = open("C:/Users/corni/Desktop/testfile.txt","wb") # wb for writing in binary mode 

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/testfile.txt","wb") # wb for writing in binary mode
    
    file.write(C) # Writes cipher byte-message into text file
    file.close() 
   
    # Desktop
    encryptedFilepath = "C:/Users/corni/Desktop/testfile.txt"

    # Laptop
    # encryptedFilepath = "C:/Users/Jonah/Desktop/378Lab/testfile.txt"

    # Decyption
    M = myFileDecrypt(key, IV, encryptedFilepath)
    print("Writing decrypted File")

    # DESKTOP
    file = open("C:/Users/corni/Desktop/outputfile.jpg","wb") # wb for writing in binary mode

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/outputfile.jpg","wb") # wb for writing in binary mode
    
    file.write(M) # Writes cipher byte-message into text file
    file.close() 
    

def mainMACLaptop():
    
     # File path for desktop
    desktopFilePath = "C:/Users/corni/Desktop/panda.jpg"
    laptopFilePath = "C:/Users/Jonah/Desktop/378Lab/---.jpg"

    # File encryption (NON-MAC)
    
    # Desktop
    C, IV, tag, EncKey, HMACKey, ext = MyFileEncryptMAC(desktopFilePath)

    # Laptop
    # C, IV, key, ext = myFileEncrypt(laptopFilePath)

    # Store encrypted data in a text file
    print("Writing encrypted File")
    
    # DESKTOP
    file = open("C:/Users/corni/Desktop/testfile.txt","wb") # wb for writing in binary mode 

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/testfile.txt","wb") # wb for writing in binary mode
    
    file.write(C) # Writes cipher byte-message into text file
    file.close() 
   
    # Desktop
    encryptedFilepath = "C:/Users/corni/Desktop/testfile.txt"

    # Laptop
    # encryptedFilepath = "C:/Users/Jonah/Desktop/378Lab/testfile.txt"


    # Message verification
    print("\nVerifying message:")
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(C)
    receiverTag = h.finalize()

    M = MydecryptMAC(C, IV, tag, EncKey, HMACKey, encryptedFilepath)
        
    print("Writing decrypted File")

    # DESKTOP
    file = open("C:/Users/corni/Desktop/outputfileYYY.jpg","wb") # wb for writing in binary mode

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/outputfile.jpg","wb") # wb for writing in binary mode
    
    file.write(M) # Writes cipher byte-message into text file
    file.close() 

# mainMACDesktop()

# if __name__ == '__main__':
#     main()