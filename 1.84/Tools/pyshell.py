"""
A simple python shell wrapper mostly based on this:
http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/355319

"""

__VERSION__ = '1.0'

import sys
from code import InteractiveConsole

class FileCacher:
    "Cache the stdout/stderr text so we can analyze it before returning it"
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
        self.stderr = sys.stderr
        self.stdout_cacher = FileCacher()
        self.stderr_cacher = FileCacher()
        InteractiveConsole.__init__(self)
        return

    def get_stdout(self): 
        sys.stdout = self.stdout_cacher
        self.stdout_cacher

    def get_stderr(self):
        sys.stderr = self.stderr_cacher
        self.stderr_cacher

    def return_stdout(self): 
        sys.stdout = self.stdout

    def return_stderr(self):
        sys.stderr = self.stderr

    def push(self,line):
        self.get_stdout()
        self.get_stderr()
        InteractiveConsole.push(self,line)
        self.return_stdout()
        self.return_stderr()

        stdout_output = self.stdout_cacher.flush()
        stderr_output = self.stderr_cacher.flush()

        return (stdout_output, stderr_output)
