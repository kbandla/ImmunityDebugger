#!/usr/bin/env python
"""
Example file for Immunity Debugger API

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__ = '1.0'

import immlib



def main():
    imm = immlib.Debugger()
    pslist=imm.ps()
    for process in pslist:
        imm.Log("Process: %s - PID: %d" % (process[1],process[0]))

if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"