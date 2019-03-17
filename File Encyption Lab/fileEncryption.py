import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# (C, IV)= Myencrypt(message, key):

# In this method, you will generate a 16 Bytes IV, 
# and encrypt the message using the key and IV in CBC mode (AES).  
# You return an error if the len(key) < 32 (i.e., the key has to be 32 bytes= 256 bits).

def myEncrypt(message, key):


    if(len(key) < 32):
        raise Exception('Key length is less than the required 32 bits')

    # generate a 16 Bytes IV
    # IV is used so if we encrypt an identical piece of data that it 
    # comes out encrypted different each time its encrypted
    backend = default_backend()
    IV = os.urandom(16) # Because 16 byte blocks

    # print("Before:")
    # print(message[0:100])

    # USE PKCS7 TO PAD!!!
    # https://cryptography.io/en/latest/hazmat/primitives/padding/
    padder = padding.PKCS7(128).padder()
    padMessage = padder.update(message)
    padMessage += padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)    #Cipher objects combine an algorithm such as AES with a mode like CBC
                                                                            # Notice we pass in the (key) to our AES argument, and (IV) to our CBC mode
    encryptor = cipher.encryptor()
    C = encryptor.update(padMessage) + encryptor.finalize()                    # Cipher text = encypt message + finalize encryption

    return(C,IV)

    
def myFileEncrypt(filepath):

    # In this method, you'll generate a 32Byte key. You open and read the file as a string. 
    # You then call the above method to encrypt your file using the key you generated. 
    # You return the cipher C, IV, key & the extension of the file (as a string).

    key = os.urandom(32) # Generate 32 Byte key
    
    with open(filepath, "rb") as ext: # Open file
        photoBits = b''.join(ext.readlines()) 

    C, IV = myEncrypt(photoBits, key)

    message = photoBits
    HMACKey = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())

    C, IV, tag = MyencryptMAC(message, key, HMACKey)
    
    return(C, IV, key, ext)


def myDecrypt(C, IV, key):

    # Everything is the same as encyption, just have to make sure to unpad
    # Made mistake of forgetting to do this

    if(len(key) < 32):
        raise Exception('Key length is less than the required 32 bits')
    
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend) 
    decryptor = cipher.decryptor()

    M = decryptor.update(C) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()

    # MISTAKE
    # Kept getting invalid padding bytes error, it was because I did unpadder.update(C) with the original ciphertext
    # Not the decrypted text 
    unpaddedMessage = unpadder.update(M) + unpadder.finalize()

    return unpaddedMessage


def myFileDecrypt(key, IV, inputFilepath):

    # Read encypted data back
    with open(inputFilepath, "rb") as ext: # Open file

        # MISTAKE, was using below line to read in as a string
        #encryptedPhotoString = base64.b64encode(ext.read()) # Read as string
        encryptedPhotoString = b''.join(ext.readlines())                        

    M = myDecrypt(encryptedPhotoString, IV, key)
    
    return M


def MyencryptMAC(message, EncKey, HMACKey):

    h = hmac.HMAC(EncKey,  hashes.SHA256(), backend = default_backend())
    h.update(bmessage)

    return C, IV, tag

    
def main():

    # File path for desktop
    desktopFilePath = "C:/Users/corni/Desktop/panda.jpg"
    laptopFilePath = "C:/Users/Jonah/Desktop/378Lab/---.jpg"

    # File encryption
    
    # Desktop
    C, IV, key, ext = myFileEncrypt(desktopFilePath)

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

    # Decyption
    M = myFileDecrypt(key, IV, encryptedFilepath)
    print("Writing decrypted File")

    # DESKTOP
    file = open("C:/Users/corni/Desktop/outputfile.jpg","wb") # wb for writing in binary mode

    # LAPTOP
    #file = open("C:/Users/Jonah/Desktop/378Lab/outputfile.jpg","wb") # wb for writing in binary mode
    
    file.write(M) # Writes cipher byte-message into text file
    file.close() 
    

    

if __name__ == '__main__':
    main()
