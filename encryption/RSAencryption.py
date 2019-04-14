from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from os import getcwd, listdir, remove
from os.path import isfile
from json import dump
from sys import argv

from handlers import cd
from encryption import myFileEncryptMAC

'''

'''

# Debug flag for testing purposes
DEBUG = False

try:
    RSA_PRIVATE_KEY_PASSWORD = argv[1]
except:
    print('Usage:\n>> python RSAencryption.py <private key encryption password>')
    exit(1)

# Get directory of script
CWD = getcwd()

# Initialize key paths relative to script directory {CWD}
RSA_PRIVATE_KEY_PATH = f'{CWD}/keys/private_key.pem'
RSA_PUBLIC_KEY_PATH = f'{CWD}/keys/public_key.pem'

BACKEND = default_backend()

def myRSAEncrypt(filepath, RSA_Publickey_filepath=RSA_PUBLIC_KEY_PATH):
    C, IV, tag, Enckey, HMACKey, ext = myFileEncryptMAC(filepath)

    try:
        with open(RSA_Publickey_filepath, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=BACKEND)
    except FileNotFoundError as e:
        print('A public key was missing at the specified path.')
        # TO-DO: Generate RSA key pair if .pem file does not exist
    
    # 
    RSACipher = public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))

    return (RSACipher, C, IV, tag, ext)

def myRSADecrypt(RSACipher, C, IV, tag, ext, RSA_Privatekey_filepath=RSA_PRIVATE_KEY_PATH):

    try:
        with open(RSA_Privatekey_filepath, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=RSA_PRIVATE_KEY_PASSWORD, backend=BACKEND)
    except FileNotFoundError as e:
        print('A private key was missing at the specified path.')

    result = private_key.decrypt(RSACipher, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    return result


def main():

    # Check if .pem file for private key exists
    if not(isfile(RSA_PRIVATE_KEY_PATH)):
        print('A .pem file containing a private key is missing. Generating a new one...')
        key_passphrase = input()
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
        with open(RSA_PRIVATE_KEY_PATH, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(RSA_PRIVATE_KEY_PASSWORD)
            ))
        with open(RSA_PUBLIC_KEY_PATH, 'wb') as f:
            f.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    # Initialize target directory to encrypt relative to directory of script {CWD}
    TARGET_DIR = f'{CWD}/files-to-RSA-encrypt'
    target_files = listdir(TARGET_DIR)

    # cd is a contextmanager that ensures all operations are
    # executed within the target directory
    with cd(TARGET_DIR):
        for filename in target_files:
            # Initialize JSON output as dictionary
            output = dict()

            # NOTE: Can be written in one line
            RSACipher, C, IV, tag, ext = myRSAEncrypt(filename) 
            output['RSACipher'] = RSACipher
            output['C'] = C
            output['IV'] = IV
            output['tag'] = tag
            output['ext'] = ext

            # TO-DO: Need to solve encoding
            with open(f'{filename}-out.json', 'wb') as fp:
                dump(output, fp)
            
            # Delete original file using os module
            remove(filename)



    
    for result in results:
        

if __name__ == '__main__':
    main()
