from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import os
from handlers import cd

'''
    This module AES encrypts files with CBC mode.
'''

BACKEND = default_backend()

def myEncrypt(message, key):
    '''
        Encrypt data with a given key.
    '''
    if len(key) < 32:
        return Exception("Key length must be at least 32.")
    
    # Generate random 16 Bytes
    IV = os.urandom(16)

    # Initialize encryption object
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=BACKEND)
    encryptor = cipher.encryptor()
    
    # Initialize padding object
    padder = padding.PKCS7(128).padder()

    # Append padding to message and close padding object
    p_message = padder.update(message) + padder.finalize()

    # Encrypt the padded message and close encryption object
    C = encryptor.update(p_message) + encryptor.finalize()

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

def myDecrypt(encrypted_message, key, IV):
    '''
        Decrypt data with a given key
    '''

    # Initialize decryption object
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=BACKEND)
    decryptor = cipher.decryptor()

    # Decrypt the encrypted message
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Initialize unpadding object
    unpadder = padding.PKCS7(128).unpadder()

    # Unpad the decrypted message
    M = unpadder.update(decrypted_message) + unpadder.finalize()

    return M

def myFileDecrypt(filename, key, IV):
    '''
        Decrypt a file with a given key.
    '''
    # Open encrypted file and save the bytes
    with open(filename, 'rb') as f:
        print('Reading file...')
        content = b''.join(f.readlines())

    result = myDecrypt(content, key, IV)
    
    return result


def main():

    # Paths to input and output folders
    INPUT_DIR = 'input' 
    OUTPUT_DIR = 'output'

    # Sample image file 
    filename = 'smile.jpg'

    # Encrypt the file
    C, IV, key, ext = myFileEncrypt(f'{INPUT_DIR}/{filename}')

    # Save the encrypted file
    with open(f'{OUTPUT_DIR}/encrypted_file{ext}', 'wb') as f:
        print('Saving encrypted file...')
        f.write(C)

    # Decrypt file
    M = myFileDecrypt(f'{OUTPUT_DIR}/encrypted_file{ext}', key, IV)

    # Save decrypted file
    with open(f'{OUTPUT_DIR}/decrypted_file{ext}','wb') as f:
        print('Saving decrypted file...')
        f.write(M)

    print('Done.')
    
if __name__ == '__main__':
    main()