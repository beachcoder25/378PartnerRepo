import os
from cryptography.hazmat.primiteives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# (C, IV)= Myencrypt(message, key):
def myEncrypt(message, key):
