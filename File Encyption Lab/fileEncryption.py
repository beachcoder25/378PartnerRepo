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
    C = encryptor.update(padMessage) + encryptor.finalize()                    # Cipher text = encypt message + finalize encryption
                                                                            # Message now encrypted
     
    print(C)

    
def myFileEncrypt(filepath):

    # In this method, you'll generate a 32Byte key. You open and read the file as a string. 
    # You then call the above method to encrypt your file using the key you generated. 
    # You return the cipher C, IV, key and the extension of the file (as a string).

    key = os.urandom(32)
    # stringList = []
    encryptTextString = ""
    encryptPhotoString = ""

    
    with open("C:/Users/corni/Desktop/trumpcat.jpg", "rb") as imageFile:
        str = base64.b64encode(imageFile.read())
        print(str)
    



    # ENCRYPTING A TEXT FILE
    textFile = open(filepath, 'r') # Returns file object, with read privileges
    
    for line in textFile:
        encryptTextString += line

    print("In myFileEncrypt Method")
    print(encryptTextString)

    byteString = encryptTextString.encode()
    myEncrypt(byteString, key)

    

    


def main():

    key = os.urandom(32)
    message1 = b"a secret message"
    message = b"sixteen  letterssixteen  let"
    

    desktopFilePath = 'C:/Users/corni/Desktop/378TestFile.txt'
    
    with open("C:/Users/corni/Desktop/trumpcat.jpg", "rb") as imageFile:
        str = base64.b64encode(imageFile.read())
        print(str)

    # myEncrypt(message, key)
    # myFileEncrypt(desktopFilePath)

if __name__ == '__main__':
    main()
