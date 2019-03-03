from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
from handlers import cd

'''
    This module AES encrypts files with CBC mode.
'''

def myEncrypt(message, key):
    '''
        Encrypt a message with a given key.
    '''
    if len(key) < 32:
        return Exception("Key length must be at least 32.")
    
    backend = default_backend()
    
    IV = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    # TO-DO: Must add padding to satisfy block size requirement
    C = encryptor.update(message) + encryptor.finalize()

    return (C, IV)

    
def myFileEncrypt(filename):
    '''
        Encrypt a file with a randomly generated 32-bit key.
    '''

    # Open image file and save the bytes
    with open(filename, 'rb') as f:
        print('Reading file...')
        content = b''.join(f.readlines())

    # Get file extension
    ext = os.path.splitext(filename)[1]

    # Generate random key
    key = os.urandom(32)

    # Encrypt the contents of the file
    C, IV = myEncrypt(content, key)

    return (C, IV, key, ext)

def main():

    # Paths to input and output folders
    INPUT_DIR = 'input' 
    OUTPUT_DIR = 'output'

    # Sample image file 
    input_file = 'smile.jpg'

    # Encrypt the file
    C, IV, key, ext = myFileEncrypt(f'{INPUT_DIR}/{filename}')

    # Save the encrypted file
    with open(f'{OUTPUT_DIR}/encrypted_file{ext}', 'wb') as f:
        print('Saving file...')
        f.write(C)

    print('Done.')
    
if __name__ == '__main__':
    main()