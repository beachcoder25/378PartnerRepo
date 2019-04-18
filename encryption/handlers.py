from os import getcwd, chdir, walk
from os.path import join
from contextlib import contextmanager

'''
    This module contains handlers for generic situations.
'''

@contextmanager
def cd(dest):
    '''
        This function safely enters and exits a directory. 

        Usage:
            with cd("/path/to/directory"):
                # Code
    '''
    origin = getcwd()
    try:
        yield chdir(dest)
    finally:
        chdir(origin)

def getAllFiles(rootPath='.'):
    '''
        Creates a list of all files located within a directory tree.
    '''
    files_found = []
    for root, dirs, files in walk(rootPath, topdown=False):
        for name in files:
            files_found.append(join(root, name))
        for name in dirs:
            # Recursive call on subdirectories
            files_found.append(getAllFiles(join(root, name)))
    
    return files_found