import os
import cryptography
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

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
    IV = os.urandom(16)

    #print("Before:")
    #print(message[0:100])

    # USE PKCS7 TO PAD!!!
    # https://cryptography.io/en/latest/hazmat/primitives/padding/
    padder = padding.PKCS7(128).padder()
    padMessage = padder.update(message)
   

    padMessage += padder.finalize()
    
    
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)    #Cipher objects combine an algorithm such as AES with a mode like CBC
                                                                            # Notice we pass in the (key) to our AES argument, and (IV) to our CBC mode
    encryptor = cipher.encryptor()
    C = encryptor.update(padMessage) + encryptor.finalize()                    # Cipher text = encypt message + finalize encryption
    #print("After:")
    #print(C[0:100])                                                                        # Message now encrypted
    
    
    # print(C)
    # print("\n\n\n\n")
    # print(IV)
    # print("HEYHEYHEY")
    return(C,IV)

    
def myFileEncrypt(filepath):

    # In this method, you'll generate a 32Byte key. You open and read the file as a string. 
    # You then call the above method to encrypt your file using the key you generated. 
    # You return the cipher C, IV, key and the extension of the file (as a string).

    key = os.urandom(32) # Generate 32 Byte key
    # stringList = []
    encryptTextString = ""
    photoString = ""

    # Works!
    with open(filepath, "rb") as ext: # Open file
        photoString = base64.b64encode(ext.read()) # Read as string

    #print(photoString)
    #print("\n\nOK\n\n")

    C, IV = myEncrypt(photoString, key)

    print("\nCipherText:")
    print(C[0:5])
    print("\nInitialization Vector: ")
    print(IV)
    print("\nKey:")
    print(key)
    ext = filepath
    
    return(C, IV, key, ext)
    
    
        


    # ENCRYPTING A TEXT FILE
    # textFile = open(filepath, 'r') # Returns file object, with read privileges
    
    # for line in textFile:
    #     encryptTextString += line

    # print("In myFileEncrypt Method")
    # print(encryptTextString)

    # byteString = encryptTextString.encode()

def main():

    # File path for desktop
    desktopFilePath = "C:/Users/corni/Desktop/trumpcat.jpg"

    # File encryption
    C, IV, key, ext = myFileEncrypt(desktopFilePath)

    # Store encrypted data in a text file
    file = open("C:/Users/corni/Desktop/testfile.txt","wb") # wb for writing in binary mode
    file.write(C) # Writes cipher byte-message into text file
    file.close() 
    print(ext)


if __name__ == '__main__':
    main()
