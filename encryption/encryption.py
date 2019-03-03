from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import os
from handlers import cd

'''
    This module encrypts files with AES and CBC mode.
'''

def myEncrypt(message, key):
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
    with open(filename, 'rb') as f:
        content = b''.join(f.readlines())

    # Get file extension
    ext = os.path.splitext(filename)[1]

    # Generate random key
    key = os.urandom(32)

    C, IV = myEncrypt(content, key)

    return (C, IV, key, ext)

def main():
    INPUT_DIR = 'input'
    OUTPUT_DIR = 'output'

    input_file = 'smile.jpg'
    # Encrypt the file
    result = myFileEncrypt(f'{INPUT_DIR}/{filename}')

    # Save the encrypted file
    with open(f'{OUTPUT_DIR}/encrypted_file{result[3]}', 'wb') as f:
        f.write(result[0])
    
if __name__ == '__main__':
    main()