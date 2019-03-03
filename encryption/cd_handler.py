from os import getcwd, listdir, chdir
from contextlib import contextmanager


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