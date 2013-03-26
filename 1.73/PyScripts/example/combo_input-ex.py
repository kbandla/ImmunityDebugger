#!/usr/bin/env python
"""
Example Combobox/InputBox file for Immunity Debugger API

(c) Immunity, Inc. 2004-2007


U{Immunity Inc.<http://www.immunityinc.com>} 

"""

__VERSION__='1.0'

import immlib
from immutils import *


def main(): 
    imm = immlib.Debugger()
    #combobox example
    combo_list=["Item a","Item b","Item c","Item d","Item e"]
    res=imm.comboBox("The title of my combobox", combo_list)
    imm.Log("Picked Item : %s" % res)
    
    
    #inputbox example
    res=imm.inputBox("This is my inputbox")
    imm.Log("Inputbox String: %s" % res)

if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"