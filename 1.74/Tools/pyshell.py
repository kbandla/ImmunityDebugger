"""
A simple python shell wrapper mostly based on this:
http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/355319

"""

__VERSION__ = '1.0'

import sys
from code import InteractiveConsole

class FileCacher:
    "Cache the stdout text so we can analyze it before returning it"
    def __init__(self): 
        self.reset()
    def reset(self): 
        self.out = []
    def write(self,line): 
        self.out.append(line)
    def flush(self):
        output=''.join(self.out)
        self.reset()
        return output
        

class Shell(InteractiveConsole):
    "Wrapper around Python that can filter input/output to the shell"
    def __init__(self):
        self.stdout = sys.stdout
        self.cache = FileCacher()
        InteractiveConsole.__init__(self)
        return

    def get_output(self): 
        sys.stdout = self.cache
        self.cache

    def return_output(self): 
        sys.stdout = self.stdout

    def push(self,line):
        self.get_output()
        InteractiveConsole.push(self,line)
        self.return_output()
        output = self.cache.flush()
        if len(output) > 0:
            return output
        return ""

     

     